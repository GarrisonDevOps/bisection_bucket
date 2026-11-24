# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class PayloadProcessor < ::Gitlab::Checks::SecretPushProtection::Base
        PAYLOAD_BYTES_LIMIT = 1.megabyte # https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/secret_detection/#target-types
        PATHS_BATCH_SIZE = 50 # number of paths per Gitaly diff_blobs batch

        # HUNK_HEADER_REGEX matches a line starting with @@, followed by - and digits (starting line number
        # and range in the original file, comma and more digits optional), then + and digits (starting line number
        # and range in the new file, comma and more digits optional), ending with @@.
        # Allows for optional section headings after the final @@.
        HUNK_HEADER_REGEX = /\A@@ -\d+(,\d+)? \+(\d+)(,\d+)? @@.*\Z/
        HUNK_MARKER = '@@'
        DIFF_ADDED_LINE = '+'
        DIFF_REMOVED_LINE = '-'
        DIFF_CONTEXT_LINE = ' '
        END_OF_DIFF = '\\'

        # https://gitlab.com/gitlab-org/gitlab/-/issues/584980#note_2993374102
        MAX_CHANGED_PATHS = 3150
        # Conservative threshold to prevent timeouts. Dark launch testing showed requests
        # with 400k+ lines consistently timeout. Set to 350k as a safe margin.
        # See: https://gitlab.com/gitlab-org/gitlab/-/work_items/588986
        MAX_LINES_PER_REQUEST = 350_000

        LOG_MESSAGES = {
          invalid_encoding: "Could not convert data to UTF-8 from %{encoding}",
          paths_sent_to_scan: "Number of changed paths broken down by their type",
          populated_lookup_map: "Populated the lookup map used to associate a " \
            "finding to commit sha + file path",
          total_lines: "Total number of lines to scan"
        }.freeze

        # The `standardize_payloads` method gets payloads containing git diffs
        # and converts them into a standardized format. Each payload is processed to include
        # its `id`, `data`, and `offset` (used to calculate the line number that a secret is on).
        # This ensures consistency between different payload types (e.g., git diffs and full files) for scanning.
        # For a more thorough explanation of the diff parsing logic, see the comment above the `parse_diffs` method.

        def standardize_payloads
          # The lookup map is used to store and lookup the payloads metadata (commit sha / file path)
          lookup_map = Hash.new { |h, id| h[id] = [] }

          payloads = get_diffs(lookup_map)

          total_lines = payloads.sum { |diff| diff.patch.lines.size }
          total_payload_bytes = payloads.sum { |diff| diff.patch.bytesize }
          secret_detection_logger.info(
            build_structured_payload(
              message: LOG_MESSAGES[:total_lines],
              total_lines: total_lines,
              total_payload_bytes: total_payload_bytes
            )
          )

          raise TooManyLinesError.new(total_lines, MAX_LINES_PER_REQUEST) if total_lines > MAX_LINES_PER_REQUEST

          payloads = payloads.flat_map do |payload|
            p_ary = parse_diffs(payload)
            build_payloads(p_ary)
          end

          results = payloads.compact.empty? ? nil : payloads

          [results, lookup_map]
        end

        # The parse_diffs method processes a diff patch to extract and group all added lines
        #   based on their position in the file.
        #
        # If the line starts with "@@", it is the hunk header, used to calculate the line offset.
        # If the line starts with "+", it is newly added in this commit,
        #   and we append the line content to a buffer and track the current line offset.
        #   If consecutive lines are added, they are grouped together in the same string with a shared offset value.
        # If the line starts with " ", it is a context line,
        #   just increment the offset counter to maintain accurate line numbers.
        # Lines starting with "-" (removed lines) and "\\" (end of diff) are ignored.
        #
        # Once the entire diff is parsed, the method returns an array of hashes containing:
        # - `id`: The id of the blob that the diff corresponds to (`diff.right_blob_id`).
        # - `data`: A string representing the concatenated added lines.
        # - `offset`: An integer indicating the line number in the file where this group of added lines starts.
        #
        # So for this example diff:
        #
        # @@ -0,0 +1,2 @@
        # +new line
        # +another added line in the same section
        # @@ -7,1 +8,2 @@
        #  unchanged line here
        # +another new line
        #
        # We would process it into:
        #
        # [{
        #    id: "123abc",
        #    data: "new line\nanother added line in the same section\n",
        #    offset: 1
        #  },
        #  {
        #    id: "123abc",
        #    data: "another new line\n",
        #    offset: 8
        #  }]

        def parse_diffs(diff)
          hunk_headers = diff.patch.each_line.select { |line| line.start_with?(HUNK_MARKER) }
          invalid_hunk = hunk_headers.find { |header| !header.match(HUNK_HEADER_REGEX) }

          if invalid_hunk
            secret_detection_logger.error(
              build_structured_payload(
                message:
                "Could not process hunk header: #{invalid_hunk.strip}, skipped parsing diff: #{diff.right_blob_id}"
              )
            )
            return []
          end

          diff_parsed_lines = []
          current_line_number = 0
          added_content = +''
          offset = nil

          diff.patch.each_line do |line|
            # Parse hunk header for start line
            if line.start_with?(HUNK_MARKER)
              hunk_info = line.match(HUNK_HEADER_REGEX)
              start_line = hunk_info[2].to_i
              current_line_number = start_line - 1

              # Push previous payload if not empty
              unless added_content.empty?
                diff_parsed_lines << {
                  id: diff.right_blob_id,
                  data: added_content.delete_suffix("\n"),
                  offset: offset
                }
                added_content = +''
                offset = nil
              end

            # Line added in this commit
            elsif line.start_with?(DIFF_ADDED_LINE)
              added_content << line[1..] # Add the line content without '+'
              current_line_number += 1
              offset ||= current_line_number

            # Context line
            elsif line.start_with?(DIFF_CONTEXT_LINE)
              unless added_content.empty?
                diff_parsed_lines << {
                  id: diff.right_blob_id,
                  data: added_content.delete_suffix("\n"),
                  offset: offset
                }
                added_content = +''
                offset = nil
              end

              current_line_number += 1
            elsif line.start_with?(DIFF_REMOVED_LINE, END_OF_DIFF)
              # Line removed in this commit or no newline marker, do not increment line number
              next
            end
          end

          # Push the final payload if not empty
          unless added_content.empty?
            diff_parsed_lines << {
              id: diff.right_blob_id, data: added_content.delete_suffix("\n"), offset: offset
            }
          end

          diff_parsed_lines
        end

        def build_payloads(data)
          data.filter_map { |datum| build_payload(datum) } # filter out nil values
        end

        def build_payload(datum)
          return datum if datum.is_a?(::Gitlab::SecretDetection::GRPC::ScanRequest::Payload)

          original_encoding = datum[:data].encoding

          unless original_encoding == Encoding::UTF_8
            datum[:data] = datum[:data].dup.force_encoding('UTF-8') # Incident 19090 (https://gitlab.com/gitlab-com/gl-infra/production/-/issues/19090)
          end

          unless datum[:data].valid_encoding?
            log_msg = format(LOG_MESSAGES[:invalid_encoding], { encoding: original_encoding })
            secret_detection_logger.warn(
              build_structured_payload(message: log_msg)
            )
            return
          end

          ::Gitlab::SecretDetection::GRPC::ScanRequest::Payload.new(
            id: datum[:id],
            data: datum[:data], # Incident 19090 (https://gitlab.com/gitlab-com/gl-infra/production/-/issues/19090)
            offset: datum.fetch(:offset, nil)
          )
        end

        private

        def diff_blobs(paths_slice)
          blob_pair_ids = paths_slice.filter_map do |path|
            next if path.old_blob_id == path.new_blob_id

            Gitaly::DiffBlobsRequest::BlobPair.new(
              left_blob: path.old_blob_id,
              right_blob: path.new_blob_id
            )
          end

          return [] if blob_pair_ids.empty?

          project.repository.diff_blobs(blob_pair_ids, patch_bytes_limit: PAYLOAD_BYTES_LIMIT).to_a
        end

        def diff_blobs_with_raw_info(paths_slice)
          raw_info_data = paths_slice.map do |path|
            params = {
              path: path.path,
              status: path.status,
              old_mode: path.old_mode.to_i(8),
              new_mode: path.new_mode.to_i(8),
              old_blob_id: path.old_blob_id.to_s,
              new_blob_id: path.new_blob_id.to_s,
              commit_id: path.commit_id.to_s
            }

            # old_path should only be set for file renames.
            # Remove this code when addressing https://gitlab.com/gitlab-org/gitlab/-/issues/568266
            params[:old_path] = path.old_path if path.old_path != path.path

            Gitaly::ChangedPaths.new(params)
          end

          begin
            project.repository.diff_blobs_with_raw_info(
              raw_info_data,
              patch_bytes_limit: PAYLOAD_BYTES_LIMIT
            ).to_a
          rescue StandardError
            secret_detection_logger.error(
              "diff_blobs_with_raw_info Gitaly call failed with args: #{raw_info_data.map(&:inspect)}"
            )
            raise
          end
        end

        def get_diffs(lookup_map)
          diffs = []

          # Get new commits
          commits = project.repository.new_commits(revisions)

          diff_filters = [
            :DIFF_STATUS_ADDED,
            :DIFF_STATUS_MODIFIED,
            :DIFF_STATUS_TYPE_CHANGE,
            :DIFF_STATUS_COPIED,
            :DIFF_STATUS_RENAMED
          ]

          # Get changed paths
          paths = project.repository.find_changed_paths(commits, merge_commit_diff_mode: :all_parents,
            find_renames: true, diff_filters: diff_filters)

          # Reject diff blob objects from paths that are excluded
          # -- TODO: pass changed paths with diff blob objects and move this exclusion process into the gem.
          paths.reject! { |changed_path| exclusions_manager.matches_excluded_path?(changed_path.path) }

          raise TooManyChangedPathsError.new(paths.size, MAX_CHANGED_PATHS) if paths.size > MAX_CHANGED_PATHS

          # This map is used later in ResponseHandler to correlate a path to a commit and file path
          populate_lookup_map(paths, lookup_map)

          audit_logger.track_changed_paths_calculated(paths.count)

          # Log only the scanned paths (so excluded paths are omitted) and break them down by type
          log_changed_paths_breakdown(paths)

          # Make multiple DiffBlobsRequests with smaller batch sizes to prevent timeout when generating diffs
          use_raw_info = Feature.enabled?(:secret_detection_transition_to_raw_info_gitaly_endpoint, project)

          paths.each_slice(PATHS_BATCH_SIZE) do |paths_slice|
            diff_slice = if use_raw_info
                           diff_blobs_with_raw_info(paths_slice)
                         else
                           diff_blobs(paths_slice)
                         end

            # Filter out diffs above 1 Megabyte and binary diffs
            filtered_diffs = diff_slice.reject { |diff| diff.over_patch_bytes_limit || diff.binary }

            diffs.concat(filtered_diffs)
          rescue GRPC::InvalidArgument => e
            ::Gitlab::ErrorTracking.track_exception(e)
          end
          diffs
        end

        def populate_lookup_map(paths, lookup_map)
          paths.each do |changed_path|
            new_blob_id = changed_path.new_blob_id.to_s

            # We have to be careful here in case new_blob_id is blank (or deletions)
            next if new_blob_id.blank? || new_blob_id == Gitlab::Git::SHA1_BLANK_SHA

            lookup_map[new_blob_id] << {
              commit_id: changed_path.commit_id.to_s,
              path: changed_path.path
            }
          end

          secret_detection_logger.info(
            build_structured_payload(
              message: LOG_MESSAGES[:populated_lookup_map],
              total_payloads: lookup_map.size,
              total_changed_path_entries: lookup_map.values.sum(&:size)
            )
          )
        end

        def log_changed_paths_breakdown(paths)
          paths_breakdown = paths.each_with_object(Hash.new(0)) do |changed_path, count|
            if changed_path.status.nil?
              count['unknown'] += 1
            else
              status = changed_path.status.to_s.downcase

              count[status] += 1
            end
          end

          secret_detection_logger.info(
            build_structured_payload(
              message: LOG_MESSAGES[:paths_sent_to_scan],
              total_paths: paths.size,
              paths_breakdown: paths_breakdown
            )
          )
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(
            e,
            project_id: project.id,
            extra: { context: 'number_of_changed_paths_calculation' }
          )
        end

        def revisions
          @revisions ||= changes_access
            .changes
            .pluck(:newrev) # rubocop:disable CodeReuse/ActiveRecord -- Array#pluck
            .reject { |r| ::Gitlab::Git.blank_ref?(r) }
            .compact
        end

        def exclusions_manager
          @exclusions_manager ||= ::Gitlab::Checks::SecretPushProtection::ExclusionsManager.new(
            project: project,
            changes_access: changes_access
          )
        end
      end
    end
  end
end
