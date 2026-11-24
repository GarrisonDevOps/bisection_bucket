# frozen_string_literal: true

module Mcp
  module Tools
    module Jobs
      class GetArtifactFileService < Base::CustomService
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize
        include ::Mcp::Tools::Concerns::UrlParser

        MAX_BYTE_LIMIT = 1.megabyte
        MIN_BYTE_OFFSET = 0
        # Zip::File.open builds one Ruby object per entry, so a small archive stuffed
        # with a huge number of tiny files is a memory bomb independent of its byte size.
        MAX_ARCHIVE_ENTRIES = 1_000
        # Zip::File.open_buffer still loads the whole central directory, and the entry
        # cap above only runs when the metadata file exists, so this bounds that load.
        MAX_ARCHIVE_BYTES = 20.megabytes
        # Reaching an offset walks everything before it: inflating it for a compressed
        # entry, or one 128 KB Range request per chunk for a stored one on object storage.
        # A stored entry cannot exceed its archive, so the archive cap bounds both.
        MAX_BYTE_OFFSET = MAX_ARCHIVE_BYTES
        # The furthest byte any window can reach. Counting past it inflates data for a
        # number no caller can use, so a gzip count stops there and reports a floor.
        MAX_COUNTED_BYTES = MAX_BYTE_OFFSET + MAX_BYTE_LIMIT
        # libgit2's binary sniff window: binary detection looks at the first 8000 bytes.
        SAMPLE_BYTES = 8000
        LISTED_PATHS_LIMIT = 20
        NOT_FOUND = 'Job not found or inaccessible'
        ARCHIVE_TYPE = 'archive'

        register_version '0.1.0', {
          toolset: :ci,
          description: 'Read a file from the artifacts of a CI/CD job as text: a file inside the artifacts ' \
            'archive, or a report artifact such as junit or sast that is stored as its own file (set ' \
            'file_type). To discover what a job or pipeline produced, use get_job or get_pipeline with ' \
            'include: artifacts. For large files, page through with byte_offset and byte_limit.',
          annotations: {
            title: 'Get job artifact file',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          },
          input_schema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'GitLab URL of the job, for example ' \
                  'https://gitlab.com/gitlab-org/gitlab/-/jobs/123. ' \
                  'Provide this, or project_id and job_id.'
              },
              project_id: {
                type: 'string',
                description: 'ID or full path of the project. Required if url is not provided.'
              },
              job_id: {
                type: 'integer',
                description: 'ID of the job. Required if url is not provided.'
              },
              artifact_path: {
                type: 'string',
                description: 'Path of the file inside the artifacts archive, for example coverage/index.html. ' \
                  'Required when file_type is archive.'
              },
              file_type: {
                type: 'string',
                description: 'Type of artifact to read. Omit to read the zip archive collected from ' \
                  'artifacts:paths. For a report stored as its own file, pass its artifacts:reports type, ' \
                  'for example junit or sast; artifact_path is then not needed.'
              },
              byte_offset: {
                type: 'integer',
                minimum: MIN_BYTE_OFFSET,
                maximum: MAX_BYTE_OFFSET,
                description: 'Byte offset to start reading the file from.'
              },
              byte_limit: {
                type: 'integer',
                minimum: 1,
                maximum: MAX_BYTE_LIMIT,
                description: 'Maximum number of bytes to return.'
              }
            }
          }
        }

        # A job we cannot find and a job we cannot read get the same response, so the caller
        # cannot probe for jobs they have no access to.
        override :authorization_error_message
        def authorization_error_message
          NOT_FOUND
        end

        protected

        # Unlike read_build, this folds in the project's artifact-access settings,
        # matching the REST artifact download endpoints.
        def auth_ability
          :read_job_artifacts
        end

        def granular_permissions
          [:download_job_artifact]
        end

        def auth_target(params)
          @arguments = params[:arguments] || {}

          job || raise(ResourceNotFoundError, NOT_FOUND)
        end

        def perform_default(arguments = {})
          @arguments = arguments || {}

          return read_standalone_artifact unless file_type == ARCHIVE_TYPE

          return excluded_response(artifact_path) if file_excluded?(job.project, artifact_path)
          # available_artifacts?, not artifacts?: artifacts past expire_at but kept by
          # "Keep artifacts from most recent successful jobs" stay downloadable.
          return no_archive_error unless job.available_artifacts?
          return archive_too_large_error if job.artifacts_size > MAX_ARCHIVE_BYTES
          return too_many_entries_error if archive_entry_count_exceeded?
          return entry_not_found_error if metadata_says_missing?

          read_from_archive
        end

        private

        attr_reader :arguments

        def job
          project = find_project!(target[:project])

          # Same lookup as `find_build!` in lib/api/helpers.rb, which backs the REST artifact routes.
          # rubocop:disable Database/AvoidUnpartitionedCiRelations -- no partition key available
          project.builds.find_by_id(target[:job_id])
          # rubocop:enable Database/AvoidUnpartitionedCiRelations
        end
        strong_memoize_attr :job

        def target
          if arguments[:url].present?
            if arguments[:project_id].present? || arguments[:job_id].present?
              raise ArgumentError, 'Provide either url, or project_id and job_id, not both'
            end

            target_from_job_url(arguments[:url])
          else
            if arguments[:project_id].blank? || arguments[:job_id].blank?
              raise ArgumentError, 'Provide either url, or project_id and job_id'
            end

            { project: arguments[:project_id].to_s, job_id: arguments[:job_id] }
          end
        end
        strong_memoize_attr :target

        def target_from_job_url(url)
          parsed = parse_job_url(url, allow_artifact_path: true)
          url_artifact_path = parsed[:artifact_path]

          if url_artifact_path.present? && normalized_input_path.present? && url_artifact_path != normalized_input_path
            raise ArgumentError, "Artifact path mismatch: artifact_path is '#{normalized_input_path}' " \
              "but url contains '#{url_artifact_path}'"
          end

          { project: parsed[:project_path], job_id: parsed[:job_id] }
        end

        def artifact_path
          path = normalized_input_path

          if path.blank?
            raise ArgumentError, 'artifact_path is required to read from the artifacts archive. ' \
              'To read a report artifact stored as its own file, set file_type instead.'
          end

          raise ArgumentError, "artifact_path must be a file path, not a directory: '#{path}'" if path.end_with?('/')

          unless ::Gitlab::Ci::Build::Artifacts::Path.new(path).valid?
            raise ArgumentError, "artifact_path is not a valid path: '#{path}'"
          end

          if ::Gitlab::PathTraversal.path_traversal?(path)
            raise ArgumentError, "artifact_path must not contain a path traversal sequence: '#{path}'"
          end

          path
        end
        strong_memoize_attr :artifact_path

        # Same values the REST artifacts download endpoint accepts.
        def file_type
          type = arguments[:file_type].to_s.strip
          return ARCHIVE_TYPE if type.blank?

          unless ::Enums::Ci::JobArtifact.downloadable_types.include?(type)
            raise ArgumentError, "file_type is not a downloadable artifact type: '#{type}'. " \
              "Valid types: #{::Enums::Ci::JobArtifact.downloadable_types.join(', ')}"
          end

          type
        end
        strong_memoize_attr :file_type

        # One file per report type, so file_type selects it and artifact_path is ignored.
        def read_standalone_artifact
          artifact = job.artifact_for_type(file_type)
          # The build-level authorization covers the archive only; report artifacts
          # carry their own accessibility, as the REST download checks.
          unless artifact && ::Ability.allowed?(current_user, :read_job_artifacts, artifact)
            return no_artifact_of_type_error
          end

          path = standalone_path(artifact)
          return excluded_response(path) if file_excluded?(job.project, path)
          # Caps the stored size; the inflated bytes are streamed, never held whole.
          return artifact_too_large_error(artifact) if artifact.size.to_i > MAX_ARCHIVE_BYTES

          with_report_stream(artifact) { |stream, total_bytes| read_report(stream, total_bytes, path) }
        rescue ::Gitlab::HttpIO::FailedToGetChunkError, Errno::ENOENT, Zlib::Error
          artifact_unreadable_error
        end

        # Reports are served inflated, so the path is the runner's file name, not the .gz blob.
        def standalone_path(artifact)
          ::Enums::Ci::JobArtifact.default_file_names[file_type.to_sym] || artifact.file.filename
        end

        # Not each_blob: it inflates the whole file in memory, so a small gzip can hit the 4 GB cap.
        # A gzip report's size cannot be read up front: the trailer describes the last member only.
        def with_report_stream(artifact)
          io = artifact.file.open
          return artifact_unreadable_error unless io

          if artifact.gzip_file_format?
            stream = GzipMembers.new(io)

            yield stream, nil
          else
            yield io, artifact.size.to_i
          end
        ensure
          stream&.finish
          io&.close
        end

        # Reads across gzip members. The runner writes one member per file that
        # artifacts:reports matched, and Zlib::GzipReader stops at the end of the first.
        class GzipMembers
          attr_reader :pos

          def initialize(io)
            @io = io
            @gz = Zlib::GzipReader.new(io)
            @pos = 0
          end

          def read(length)
            buffer = String.new(capacity: length)

            while @gz && buffer.bytesize < length
              chunk = @gz.read(length - buffer.bytesize)

              if chunk.nil? || chunk.empty?
                next_member
              else
                buffer << chunk
              end
            end

            @pos += buffer.bytesize
            buffer.empty? && length > 0 ? nil : buffer
          end

          def finish
            @gz&.finish
            @gz = nil
          end

          private

          # The reader over-reads into the next member and keeps the surplus in
          # `unused`, so seek back to it and open a reader there.
          def next_member
            unused = @gz.unused
            @gz.finish
            @io.seek(-unused.bytesize, IO::SEEK_CUR) if unused

            @gz = @io.eof? ? nil : Zlib::GzipReader.new(@io)
          end
        end

        def read_report(stream, total_bytes, path)
          byte_offset = arguments[:byte_offset] || MIN_BYTE_OFFSET
          byte_limit = arguments[:byte_limit] || MAX_BYTE_LIMIT
          view_url = download_url(file_type)

          if total_bytes
            if byte_offset >= total_bytes
              return success_response(+'', byte_offset, total_bytes, truncated: false, path: path, view_url: view_url)
            end

            byte_limit = [byte_limit, total_bytes - byte_offset].min
          end

          read_stream(stream, byte_offset, byte_limit, total_bytes, path: path, view_url: view_url)
        end

        # A report has two names, the stored file get_job lists (junit.xml.gz) and the
        # one the runner collected (junit.xml); artifact_path may carry either.
        def standalone_hint
          name = File.basename(artifact_path)
          report = job.job_artifacts.all_reports.find do |artifact|
            name == artifact.filename ||
              name == ::Enums::Ci::JobArtifact.default_file_names[artifact.file_type.to_sym]
          end
          return unless report

          " The job has a #{report.file_type} report artifact with that name; " \
            "call again with {\"file_type\": \"#{report.file_type}\"}."
        end

        def normalized_input_path
          arguments[:artifact_path].to_s.strip.delete_prefix('/')
        end

        # The archive's metadata file lists every entry, so a missing path is answered
        # without downloading the archive itself.
        def metadata_says_missing?
          !!metadata_entry && !metadata_entry.exists?
        end

        # Not artifacts_metadata?: that folds in artifacts?, which is false for
        # expired-but-locked artifacts, and availability is already checked above.
        def metadata_entry
          return unless job.artifacts_metadata&.exists?

          job.artifacts_metadata_entry(artifact_path)
        end
        strong_memoize_attr :metadata_entry

        # The metadata file is written by GitLab at upload, so its size for the entry
        # is trusted over the archive's self-declared one.
        def metadata_entry_size
          metadata_entry.total_size if metadata_entry&.exists?
        end

        def archive_entry_count_exceeded?
          all_entries.present? && all_entries.length > MAX_ARCHIVE_ENTRIES
        end

        def all_entries
          return unless job.artifacts_metadata&.exists?

          job.artifacts_metadata_entry('', recursive: true).entries
        end
        strong_memoize_attr :all_entries

        def read_from_archive
          with_archive_io do |io|
            zip_file = Zip::File.open_buffer(io)
            entry = zip_file.find_entry(artifact_path)

            if entry.nil?
              entry_not_found_error
            elsif entry.ftype != :file
              not_regular_file_error
            else
              read_entry(entry)
            end
          end
        rescue ::Gitlab::HttpIO::FailedToGetChunkError, Errno::EINVAL, Zip::Error, Zlib::Error
          archive_unreadable_error
        end

        # Remote archives are read through ranged requests (central directory plus
        # the one entry) instead of downloading the whole archive to a Tempfile;
        # local storage hands back a plain File, which rubyzip reads directly.
        def with_archive_io
          io = job.artifacts_file.open
          io = RangedZipIo.new(io) if io.is_a?(::Gitlab::HttpIO)

          yield io
        ensure
          io&.close
        end

        def read_entry(entry)
          byte_offset = arguments[:byte_offset] || MIN_BYTE_OFFSET
          byte_limit = arguments[:byte_limit] || MAX_BYTE_LIMIT
          total_bytes = metadata_entry_size || entry.size

          # Returning before get_input_stream means nothing is inflated.
          return success_response(+'', byte_offset, total_bytes, truncated: false) if byte_offset >= total_bytes

          # A stored entry that over-declares its size would otherwise read neighboring
          # archive bytes into the window.
          byte_limit = [byte_limit, total_bytes - byte_offset].min

          entry.get_input_stream { |stream| read_stream(stream, byte_offset, byte_limit, total_bytes) }
        end

        # The first SAMPLE_BYTES double as the binary sniff and the head of the window.
        # A nil total_bytes is counted by reading to the end once the window is filled.
        def read_stream(stream, byte_offset, byte_limit, total_bytes, path: artifact_path, view_url: raw_artifact_url)
          sample = stream.read([SAMPLE_BYTES, total_bytes].compact.min).to_s

          if ::Gitlab::EncodingHelper.detect_libgit2_binary?(sample)
            binary_error(sample, total_bytes || consumed_bytes(stream), path: path, view_url: view_url)
          else
            content, more_data = window_from(stream, sample, byte_offset, byte_limit)
            exact = !total_bytes.nil?
            total_bytes ||= consumed_bytes(stream)
            exact ||= total_bytes < MAX_COUNTED_BYTES
            truncated = more_data && byte_offset + content.bytesize < total_bytes

            success_response(content, byte_offset, total_bytes, truncated: truncated, exact: exact,
              path: path, view_url: view_url)
          end
        end

        # The zip stream cannot seek, so the window is the already-read binary sample plus
        # sequential reads. "More data" is probed from the stream, not the declared size: a
        # corrupt entry that under-delivers must not report truncated or the agent loops.
        def window_from(stream, sample, byte_offset, byte_limit)
          content = if byte_offset < sample.bytesize
                      head = sample.byteslice(byte_offset, byte_limit)
                      remaining = byte_limit - head.bytesize

                      remaining > 0 ? head + stream.read(remaining).to_s : head
                    else
                      discard(stream, byte_offset - sample.bytesize)
                      stream.read(byte_limit).to_s
                    end

          more_in_sample = byte_offset + content.bytesize < sample.bytesize
          [content, more_in_sample || !stream.read(1).to_s.empty?]
        end

        # Skipped bytes are read in small chunks instead of one read, so a large
        # byte_offset does not allocate the skipped part of the file in memory.
        def discard(stream, count)
          while count > 0
            chunk = stream.read([count, 128.kilobytes].min)
            break if chunk.nil? || chunk.empty?

            count -= chunk.bytesize
          end
        end

        # Chunks are dropped as they are counted, so memory stays at one chunk, and the
        # work per call is bounded by MAX_COUNTED_BYTES rather than by the file.
        def consumed_bytes(stream)
          while stream.pos < MAX_COUNTED_BYTES
            chunk = stream.read([128.kilobytes, MAX_COUNTED_BYTES - stream.pos].min)
            break if chunk.nil? || chunk.empty?
          end

          stream.pos
        end

        def success_response(
          content, byte_offset, total_bytes, truncated:, exact: true, path: artifact_path, view_url: raw_artifact_url)
          returned_start = [byte_offset, total_bytes].min
          returned_end = returned_start + content.bytesize

          system_instruction = truncation_instruction(total_bytes, returned_end, view_url, exact: exact) if truncated

          data = {
            path: path,
            job_id: job.id,
            metadata: {
              total_bytes: total_bytes,
              returned: { start: returned_start, end: returned_end },
              truncated: truncated
            },
            # Zip reads come back binary-encoded, and a byte window can split a multi-byte
            # character, so re-encode before the response is serialized to JSON.
            content: (+content).force_encoding(Encoding::UTF_8).scrub,
            system_instruction: system_instruction
          }.compact

          formatted_content = [{ type: 'text', text: Gitlab::Json.generate(data) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, data)
        end

        # The schema caps byte_offset at MAX_BYTE_OFFSET, so past it there is no next window to offer.
        def truncation_instruction(total_bytes, returned_end, view_url, exact: true)
          remaining = "#{'at least ' unless exact}#{total_bytes - returned_end} bytes"

          if returned_end > MAX_BYTE_OFFSET
            "Artifact file truncated. Remaining: #{remaining}, beyond the #{MAX_BYTE_OFFSET} bytes " \
              "this tool reads. Download it from #{view_url} instead."
          else
            "Artifact file truncated. Remaining: #{remaining}. " \
              "Call again with {\"byte_offset\": #{returned_end}}."
          end
        end

        def no_archive_error
          message = "Job #{job.id} has no artifacts archive."
          message += ' The artifacts have expired.' if job.artifacts_expired?
          message += standalone_hint.to_s

          error(message, reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND)
        end

        def too_many_entries_error
          error("The artifacts archive of job #{job.id} has more than #{MAX_ARCHIVE_ENTRIES} entries, " \
            "which exceeds what this tool reads. Download it from #{download_url} instead.",
            reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST)
        end

        def archive_too_large_error
          error("The artifacts archive of job #{job.id} is #{job.artifacts_size} bytes, which exceeds " \
            "the #{MAX_ARCHIVE_BYTES} bytes this tool reads. Download it from #{download_url} instead.",
            reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST)
        end

        def archive_unreadable_error
          error("Could not read the artifacts archive of job #{job.id}. Download it from #{download_url} instead.",
            reason: ::Mcp::Tools::Base::Response::Reason::ERROR)
        end

        def no_artifact_of_type_error
          message = "Job #{job.id} has no #{file_type} artifact."
          message += ' The artifacts have expired.' if job.artifacts_expired?

          error(message, reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND)
        end

        def artifact_too_large_error(artifact)
          error("The #{file_type} artifact of job #{job.id} is #{artifact.size} bytes, which exceeds " \
            "the #{MAX_ARCHIVE_BYTES} bytes this tool reads. Download it from #{download_url(file_type)} instead.",
            reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST)
        end

        def artifact_unreadable_error
          error("Could not read the #{file_type} artifact of job #{job.id}. " \
            "Download it from #{download_url(file_type)} instead.",
            reason: ::Mcp::Tools::Base::Response::Reason::ERROR)
        end

        def entry_not_found_error
          message = "Artifact file '#{artifact_path}' not found in the artifacts archive of job #{job.id}."
          paths = listable_paths
          message += " Files in the archive include: #{paths.join(', ')}." if paths.any?
          message += standalone_hint.to_s

          error(message, reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND)
        end

        def not_regular_file_error
          error("Artifact path '#{artifact_path}' in job #{job.id} is not a regular file and cannot be read.",
            reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST)
        end

        # CE has no context exclusions. Overridden in EE.
        def file_excluded?(_project, _path)
          false
        end

        def excluded_response(path)
          error("File '#{path}' is excluded from AI context by this project's settings and cannot be read.",
            reason: ::Mcp::Tools::Base::Response::Reason::UNAUTHORIZED)
        end

        def binary_error(sample, total_bytes, path: artifact_path, view_url: raw_artifact_url)
          mime_type = ::Gitlab::Utils::MimeType.from_string(sample) || 'binary'

          error("Artifact file '#{path}' in job #{job.id} is binary (#{mime_type}) and cannot be " \
            "returned as text. Size: #{total_bytes} bytes. It can be viewed at #{view_url}.",
            reason: ::Mcp::Tools::Base::Response::Reason::BAD_REQUEST)
        end

        def raw_artifact_url
          ::Gitlab::Routing.url_helpers.raw_project_job_artifacts_url(job.project, job, path: artifact_path)
        end

        def listable_paths
          return [] unless all_entries

          all_entries.keys.map(&:to_s).reject { |path| path.end_with?('/') }.first(LISTED_PATHS_LIMIT)
        rescue StandardError
          []
        end

        def download_url(type = ARCHIVE_TYPE)
          options = type == ARCHIVE_TYPE ? {} : { file_type: type }
          ::Gitlab::Routing.url_helpers.download_project_job_artifacts_url(job.project, job, **options)
        end

        def error(message, reason:)
          ::Mcp::Tools::Base::Response.error(message, reason: reason)
        end
      end
    end
  end
end

Mcp::Tools::Jobs::GetArtifactFileService.prepend_mod
