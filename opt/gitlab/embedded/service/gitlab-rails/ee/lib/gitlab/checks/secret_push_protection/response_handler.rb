# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class ResponseHandler < ::Gitlab::Checks::SecretPushProtection::Base
        DEADLINE_EXCEEDED_MESSAGE = "Deadline Exceeded"

        ERROR_MESSAGES = {
          failed_to_scan_regex_error: "\n    - Failed to scan blob(id: %{payload_id}) due to regex error.",
          blob_timed_out_error: "\n    - Scanning blob(id: %{payload_id}) timed out.",
          scan_timeout_error: 'Secret detection scan timed out.',
          invalid_input_error: 'Secret detection scan failed due to invalid input.',
          invalid_scan_status_code_error: 'Invalid secret detection scan status, check passed.'
        }.freeze

        LOG_MESSAGES = {
          secrets_not_found: 'Secret detection scan completed with no findings.',
          skip_secret_detection: "\n\nTo skip secret push protection, add the following Git push option " \
            "to your push command: `-o secret_push_protection.skip_all`",
          found_secrets: "\nPUSH BLOCKED: Secrets detected in code changes",
          found_secrets_post_message: "\n\nTo push your changes you must remove the identified secrets.",
          found_secrets_docs_link: "\nFor guidance, see %{path}",
          found_secrets_with_errors: 'Secret detection scan completed with one or more findings ' \
            'but some errors occured during the scan.',
          finding_message_occurrence_header: "\n\nSecret push protection " \
            "found the following secrets in commit: %{sha}",
          finding_message_occurrence_path: "\n-- %{path}:",
          finding_message_occurrence_line: "%{line_number} | %{description}",
          finding_message: "\n\nSecret leaked in blob: %{payload_id}" \
            "\n  -- line:%{line_number} | %{description}",
          found_secrets_footer: "\n--------------------------------------------------\n\n",
          failed_to_map_blob_to_commit_and_path: "Secret Push Protection could not map " \
            "blob %{payload_id} to commit and path"
        }.freeze

        def format_response(response, lookup_map)
          # Try to retrieve file path and commit SHA for the diffs found.
          if response.status == ::Gitlab::SecretDetection::Core::Status::FOUND ||
              response.status == ::Gitlab::SecretDetection::Core::Status::FOUND_WITH_ERRORS

            results = transform_findings(response, lookup_map)

            # If there is no findings in `response.results`, that means all findings
            # were excluded in `transform_findings`, so we set status to no secrets found.
            if response.results.empty?
              response = ::Gitlab::SecretDetection::Core::Response.new(
                status: ::Gitlab::SecretDetection::Core::Status::NOT_FOUND,
                results: []
              )
            end
          end

          case response.status
          when ::Gitlab::SecretDetection::Core::Status::NOT_FOUND
            # No secrets found, we log and skip the check.
            audit_logger.track_spp_scan_passed

            secret_detection_logger.info(build_structured_payload(message: LOG_MESSAGES[:secrets_not_found]))
          when ::Gitlab::SecretDetection::Core::Status::FOUND
            audit_logger.track_spp_push_blocked_secrets_found(response.results.size)
            log_push_blocked_audit_event(results)

            # One or more secrets found, generate message with findings and fail check.
            message = build_secrets_found_message(results)

            secret_detection_logger.info(
              build_structured_payload(message: LOG_MESSAGES[:found_secrets])
            )

            raise ::Gitlab::GitAccess::ForbiddenError, message
          when ::Gitlab::SecretDetection::Core::Status::FOUND_WITH_ERRORS
            audit_logger.track_spp_push_blocked_secrets_found_with_errors(response.results.size)
            log_push_blocked_audit_event(results)

            # One or more secrets found, but with scan errors, so we
            # generate a message with findings and errors, and fail the check.
            message = build_secrets_found_message(results, with_errors: true)

            secret_detection_logger.info(
              build_structured_payload(message: LOG_MESSAGES[:found_secrets_with_errors])
            )

            raise ::Gitlab::GitAccess::ForbiddenError, message
          when ::Gitlab::SecretDetection::Core::Status::SCAN_TIMEOUT
            # Entire scan timed out, we log and skip the check for now.
            audit_logger.log_spp_scan_timeout

            secret_detection_logger.error(
              build_structured_payload(message: ERROR_MESSAGES[:scan_timeout_error])
            )
          when ::Gitlab::SecretDetection::Core::Status::INPUT_ERROR
            # Scan failed due to invalid input. We skip the check because of an input error
            # which could be due to not having anything to scan.
            audit_logger.log_spp_invalid_input

            secret_detection_logger.error(
              build_structured_payload(message: ERROR_MESSAGES[:invalid_input_error])
            )
          else
            # Invalid status returned by the scanning service/gem, we don't
            # know how to handle that, so nothing happens and we skip the check.
            secret_detection_logger.error(
              build_structured_payload(message: ERROR_MESSAGES[:invalid_scan_status_code_error])
            )
          end
        end

        def timed_out?(response)
          response.status == ::Gitlab::SecretDetection::Core::Status::SCAN_ERROR &&
            response.metadata&.dig(:message) == DEADLINE_EXCEEDED_MESSAGE
        end

        private

        def log_push_blocked_audit_event(results)
          mapped = results[:commits].flat_map do |commit_id, paths|
            paths.flat_map do |path, path_findings|
              audited_findings(path_findings, commit_id: commit_id, file_path: path)
            end
          end

          # A blob we could not map to a commit and a path still blocked the push, so it belongs
          # in the audit trail even without those two fields.
          unmapped = results[:blobs].values.compact.flat_map { |findings| audited_findings(findings) }

          audit_logger.log_spp_push_blocked(mapped + unmapped)
        end

        def audited_findings(findings, commit_id: nil, file_path: nil)
          findings.filter_map do |finding|
            next unless finding.status == ::Gitlab::SecretDetection::Core::Status::FOUND

            { commit_id: commit_id, file_path: file_path, secret_type: finding.type }
          end
        end

        def transform_findings(response, lookup_map)
          # Let's group the findings by the blob id.
          findings_by_blobs = response.results.group_by(&:payload_id)

          # We create an empty hash for the structure we'll create later as we correlate findings to commits/paths.
          findings_by_commits = {}

          # Let's create a set to store ids of blobs with metadata (commit SHA/file path) found.
          blobs_with_metadata_found = Set.new

          # Scanning had found secrets, let's try to look up their file path and commit id. This can be done by
          # using `lookup_map` we populated in `PayloadProcessor`, and cross examining payloads
          # with ones where secrets where found.
          findings_by_blobs.each do |payload_id, findings|
            changed_paths = lookup_map[payload_id]

            # When no payload metadata exist, we move on to the next finding.
            if changed_paths.blank?
              secret_detection_logger.warn(
                build_structured_payload(
                  message: format(
                    LOG_MESSAGES[:failed_to_map_blob_to_commit_and_path],
                    payload_id: payload_id
                  )
                )
              )

              next
            end

            # We loop through the changed paths associated with the payload where this finding was detected,
            # get the path and the commit ID. If they're blank, we skip to the next one. We make sure to exclude
            # paths that match existing exclusions, then add it to the `findings_by_commits` hash.
            changed_paths.each do |changed_path|
              path      = changed_path[:path]
              commit_id = changed_path[:commit_id]

              next if path.blank? || commit_id.blank?

              # To associate each finding to a commit SHA and a path, we use nested hashes, e.g.:
              #
              #   {
              #     commit_id_1: {
              #       path_1: [finding_1, finding_2]
              #     },
              #     commit_id_2: {
              #       path_1: [finding_3],
              #       path_2: [finding_4, finding_5]
              #     }
              #   }
              #
              # And then use them to display the findings ordered by their commit SHAs and their paths.
              findings_by_commits[commit_id] ||= {}
              findings_by_commits[commit_id][path] ||= []
              findings_by_commits[commit_id][path].concat(findings)

              # Mark as found with metadata already.
              blobs_with_metadata_found << payload_id
            end

            # If this blob never made it into `findings_by_commits` (i.e. all paths excluded
            # or invalid), we remove it from `response.results` and `findings_by_blobs`.
            next if blobs_with_metadata_found.include?(payload_id)

            response.results.delete_if { |finding| finding.payload_id == payload_id }

            findings_by_blobs.delete(payload_id)
          end

          # Remove blobs that has metadata found.
          findings_by_blobs.delete_if { |payload_id, _| blobs_with_metadata_found.include?(payload_id) }

          # Return the findings as a hash sorted by commits and blobs (minus ones already found).
          {
            commits: findings_by_commits,
            blobs: findings_by_blobs
          }
        end

        def build_secrets_found_message(results, with_errors: false)
          message = with_errors ? LOG_MESSAGES[:found_secrets_with_errors] : LOG_MESSAGES[:found_secrets]

          results[:commits].each do |sha, paths|
            message += format(LOG_MESSAGES[:finding_message_occurrence_header], { sha: sha })

            paths.each do |path, findings|
              findings.each do |finding|
                message += format(LOG_MESSAGES[:finding_message_occurrence_path], { path: path })
                message += build_finding_message(finding, :commit)
              end
            end
          end

          results[:blobs].values.compact.each do |findings|
            findings.each do |finding|
              message += build_finding_message(finding, :blob)
            end
          end

          message += LOG_MESSAGES[:found_secrets_post_message]

          docs_url = Rails.application.routes.url_helpers.help_page_url(
            'user/application_security/secret_detection/secret_push_protection/_index.md',
            anchor: 'resolve-a-blocked-push'
          )

          message += format(
            LOG_MESSAGES[:found_secrets_docs_link],
            { path: docs_url }
          )

          message += LOG_MESSAGES[:skip_secret_detection]
          message += LOG_MESSAGES[:found_secrets_footer]
          message
        end

        def build_finding_message(finding, type)
          case finding.status
          when ::Gitlab::SecretDetection::Core::Status::FOUND
            # Track the secret finding in audit logs.
            audit_logger.track_secret_found(finding.description)

            if type == :commit
              build_commit_finding_message(finding)
            elsif type == :blob
              build_blob_finding_message(finding)
            end
          when ::Gitlab::SecretDetection::Core::Status::SCAN_ERROR
            format(ERROR_MESSAGES[:failed_to_scan_regex_error], { payload_id: finding.payload_id })
          when ::Gitlab::SecretDetection::Core::Status::PAYLOAD_TIMEOUT
            format(ERROR_MESSAGES[:blob_timed_out_error], { payload_id: finding.payload_id })
          end
        end

        def build_commit_finding_message(finding)
          format(
            LOG_MESSAGES[:finding_message_occurrence_line],
            {
              line_number: finding.line_number,
              description: finding.description
            }
          )
        end

        def build_blob_finding_message(finding)
          format(LOG_MESSAGES[:finding_message], finding.to_h)
        end
      end
    end
  end
end
