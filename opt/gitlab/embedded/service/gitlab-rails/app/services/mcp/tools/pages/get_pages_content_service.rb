# frozen_string_literal: true

module Mcp
  module Tools
    module Pages
      class GetPagesContentService < Base::CustomService
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize
        include ::Mcp::Tools::Concerns::UrlParser

        container_arguments project_or_group: nil, record: { url: ->(url) { governance_pages_project(url) } }

        MAX_BYTE_LIMIT = 1.megabyte
        MIN_BYTE_OFFSET = 0
        MAX_BYTE_OFFSET = 20.megabytes
        MAX_FILE_COUNT = 10_000
        # Zip::File.open_buffer loads the whole central directory, and MAX_FILE_COUNT
        # does not bound the entry names and comments in it (up to 64 KB each).
        MAX_CENTRAL_DIRECTORY_BYTES = 5.megabytes
        # libgit2's binary sniff window: binary detection looks at the first 8000 bytes.
        SAMPLE_BYTES = 8000
        INDEX_FILE = 'index.html'
        NOT_FOUND = 'Pages site not found or inaccessible'

        register_version '0.1.0', {
          toolset: :core,
          description: 'Read the content published at a GitLab Pages URL as text, including private ' \
            'Pages sites the authenticated user may view. The URL is resolved against the Pages sites ' \
            'of this GitLab instance and the file is read from the current deployment, so the result ' \
            'is what visitors see, not the repository source. A directory URL reads its index.html. ' \
            'For large files, page through with byte_offset and byte_limit.',
          annotations: {
            title: 'Get Pages content',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          },
          input_schema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'GitLab Pages URL to read, for example https://mygroup.gitlab.io/myproject/docs/. ' \
                  'Must be served by the GitLab Pages of this instance; other hosts are not fetched.'
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
            },
            required: %w[url]
          }
        }

        override :authorization_error_message
        def authorization_error_message
          NOT_FOUND
        end

        # A public site serves the same files to every reader, and project_id is shown to
        # anonymous users when they can read the project.
        override :granular_public_access_allowed?
        def granular_public_access_allowed?(project)
          ::Users::Anonymous.can?(:read_project, project)
        end

        protected

        def auth_ability
          :read_pages_content
        end

        def granular_permissions
          [:read_pages_content]
        end

        def auth_target(params)
          @arguments = params[:arguments] || {}

          raise ArgumentError, NOT_FOUND unless ::Gitlab.config.pages.enabled

          lookup_path&.deployment&.project
        end

        def perform_default(arguments = {})
          @arguments = arguments || {}

          return too_many_files_error if deployment.file_count > MAX_FILE_COUNT

          read_from_archive
        end

        private

        attr_reader :arguments

        def url
          arguments[:url].to_s
        end

        def governance_pages_project(url)
          @arguments = { url: url }

          lookup_path&.deployment&.project
        rescue ArgumentError
          nil
        end

        def deployment
          lookup_path.deployment
        end

        def project
          deployment.project
        end

        def lookup_path
          strong_memoize_with(:lookup_path, url) do
            virtual_domain = ::Gitlab::Pages::VirtualHostFinder.new(uri.host).execute
            next unless virtual_domain

            matching = virtual_domain.lookup_paths.select do |candidate|
              "#{request_path}/".downcase.start_with?(candidate.prefix.downcase)
            end

            matching.max_by { |candidate| candidate.prefix.length }
          end
        end

        def uri
          strong_memoize_with(:uri, url) do
            raise ArgumentError, 'url is missing' if url.blank?

            parse_url!(url)
          end
        end

        def request_path
          strong_memoize_with(:request_path, url) do
            path = unescape_and_scrub_uri(uri.path.presence || '/')

            if ::Gitlab::PathTraversal.path_traversal?(path)
              raise ArgumentError, "url must not contain a path traversal sequence: '#{url}'"
            end

            clean_path(path)
          end
        end

        # Like Go's path.Clean, which gitlab-pages applies, but keeps a trailing slash.
        def clean_path(path)
          segments = path.split('/').reject { |segment| segment.empty? || segment == '.' }
          cleaned = "/#{segments.join('/')}"

          segments.any? && path.match?(%r{/\.?\z}) ? "#{cleaned}/" : cleaned
        end

        def site_path
          request_path[lookup_path.prefix.chomp('/').length..].delete_prefix('/')
        end

        # Same order as gitlab-pages: the exact file, then a directory of that name
        # (even one without index.html), and only then the .html file.
        def find_entry(zip_file)
          return file_entry(zip_file, INDEX_FILE) if site_path.blank?

          name = site_path.delete_suffix('/')
          exact = file_entry(zip_file, name) unless site_path.end_with?('/')
          return exact if exact
          return file_entry(zip_file, "#{name}/#{INDEX_FILE}") if directory?(zip_file, name)

          file_entry(zip_file, "#{name}.html")
        end

        def file_entry(zip_file, name)
          entry = zip_file.find_entry(in_root(name))
          entry if entry&.ftype == :file
        end

        def directory?(zip_file, name)
          prefix = in_root("#{name}/")
          zip_file.entries.any? { |entry| entry.name.start_with?(prefix) }
        end

        def in_root(name)
          root = (deployment.root_directory.presence || 'public').chomp('/')
          root.present? ? "#{root}/#{name}" : name
        end

        def read_from_archive
          with_archive_io do |io|
            limited_io = ::Mcp::Tools::ByteLimitedIo.new(
              io, max_bytes: MAX_CENTRAL_DIRECTORY_BYTES + Zip::CentralDirectory::MAX_END_OF_CDS_SIZE
            )
            zip_file = Zip::File.open_buffer(limited_io)
            limited_io.remove_limit!

            entry = find_entry(zip_file)
            entry ? read_entry(entry) : entry_not_found_error
          end
        rescue ::Mcp::Tools::ByteLimitedIo::LimitExceeded
          central_directory_too_large_error
        rescue ::Gitlab::HttpIO::FailedToGetChunkError, Zip::Error, Zlib::Error
          archive_unreadable_error
        end

        def with_archive_io
          io = deployment.file.open
          io = RangedZipIo.new(io) if io.is_a?(::Gitlab::HttpIO)

          yield io
        ensure
          io&.close
        end

        def read_entry(entry)
          byte_offset = arguments[:byte_offset] || MIN_BYTE_OFFSET
          byte_limit = arguments[:byte_limit] || MAX_BYTE_LIMIT
          total_bytes = entry.size

          return success_response(entry, +'', byte_offset, total_bytes, truncated: false) if byte_offset >= total_bytes

          byte_limit = [byte_limit, total_bytes - byte_offset].min

          entry.get_input_stream do |stream|
            sample = stream.read([SAMPLE_BYTES, total_bytes].min).to_s

            if ::Gitlab::EncodingHelper.detect_libgit2_binary?(sample)
              binary_error(sample, total_bytes)
            else
              content, more_data = window_from(stream, sample, byte_offset, byte_limit)
              truncated = more_data && byte_offset + content.bytesize < total_bytes

              success_response(entry, content, byte_offset, total_bytes, truncated: truncated)
            end
          end
        end

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

        def discard(stream, count)
          while count > 0
            chunk = stream.read([count, 128.kilobytes].min)
            break if chunk.nil? || chunk.empty?

            count -= chunk.bytesize
          end
        end

        def success_response(entry, content, byte_offset, total_bytes, truncated:)
          returned_start = [byte_offset, total_bytes].min
          returned_end = returned_start + content.bytesize

          system_instruction = if truncated && returned_end > MAX_BYTE_OFFSET
                                 "Page content truncated. The remaining #{total_bytes - returned_end} bytes " \
                                   "start past the maximum byte_offset of #{MAX_BYTE_OFFSET} and cannot be read."
                               elsif truncated
                                 "Page content truncated. Remaining: #{total_bytes - returned_end} bytes. " \
                                   "Call again with {\"byte_offset\": #{returned_end}}."
                               end

          data = {
            url: url,
            path: entry.name,
            project_id: (project.id if ::Ability.allowed?(current_user, :read_project, project)),
            content_type: ::Rack::Mime.mime_type(File.extname(entry.name), 'application/octet-stream'),
            metadata: {
              total_bytes: total_bytes,
              returned: { start: returned_start, end: returned_end },
              truncated: truncated
            },
            content: (+content).force_encoding(Encoding::UTF_8).scrub,
            system_instruction: system_instruction
          }.compact

          formatted_content = [{ type: 'text', text: Gitlab::Json.generate(data) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, data)
        end

        # Same answer as a denied site, so a group homepage cannot be used to probe
        # which private project paths exist.
        def entry_not_found_error
          error("Tool execution failed: #{NOT_FOUND}")
        end

        def too_many_files_error
          error("The Pages deployment serving '#{url}' has more than #{MAX_FILE_COUNT} files, " \
            'which exceeds what this tool reads.')
        end

        def central_directory_too_large_error
          error("The Pages deployment serving '#{url}' has a central directory larger than " \
            "#{MAX_CENTRAL_DIRECTORY_BYTES} bytes, which exceeds what this tool reads.")
        end

        def archive_unreadable_error
          error("Could not read the Pages deployment serving '#{url}'.")
        end

        def binary_error(sample, total_bytes)
          file_type = ::Gitlab::Utils::MimeType.from_string(sample) || 'binary'

          error("The file at '#{url}' is binary (#{file_type}) and cannot be returned as text. " \
            "Size: #{total_bytes} bytes.")
        end

        def error(message)
          ::Mcp::Tools::Base::Response.error(message)
        end
      end
    end
  end
end
