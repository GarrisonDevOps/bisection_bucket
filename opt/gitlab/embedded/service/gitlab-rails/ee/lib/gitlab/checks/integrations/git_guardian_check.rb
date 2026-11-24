# frozen_string_literal: true

module Gitlab
  module Checks
    module Integrations
      class GitGuardianCheck < ::Gitlab::Checks::BaseBulkChecker
        BLOB_BYTES_LIMIT = 1.megabyte

        LOG_MESSAGE = 'Starting GitGuardian scan...'
        # Secret Push Protection is changing the skip option names to reflect the feature being renamed.
        # We want to keep the GitGuardian skip options consistent with SPP's, but changing the options here
        # would be a breaking change. To avoid a breaking change, we're keeping the old skip option names,
        # but also introduce the new options to match SPP. In 18.0, remove the old name and only support
        # the new one going forward.
        # More details: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/155922#note_1945663581
        OLD_SPECIAL_COMMIT_FLAG = /\[skip secret detection\]/i
        NEW_SPECIAL_COMMIT_FLAG = /\[skip secret push protection\]/i

        REMEDIATION_MESSAGE = <<~MESSAGE
          How to remediate:

          Since the secret was detected after the commit but before the push, you need to:

          1. Rewrite the Git history, making sure to remove the secret(s).
          2. Push again.

          For guidance, see %{path}

          [To apply with caution] If you want to bypass the secrets check:

          1. Add [skip secret push protection] flag to the commit message or add the following Git push option: `-o secret_push_protection.skip_all`.
          2. Commit and try pushing again.
        MESSAGE

        def initialize(integration_check)
          @changes_access = integration_check.changes_access
        end

        def validate!
          return unless integration_activated?
          return if skip_secret_detection?

          logger.log_timed(LOG_MESSAGE) do
            blobs = changed_blobs(timeout: logger.time_left)
            blobs.reject! { |blob| blob.size > BLOB_BYTES_LIMIT || blob.binary }

            format_git_guardian_response do
              repository_url = GitGuardianProjectUrlHeader.build(project)
              project.git_guardian_integration.execute(blobs, repository_url)
            end
          end
        end

        private

        def integration_activated?
          integration = project.git_guardian_integration

          integration.present? && integration.activated?
        end

        def changed_blobs(timeout:)
          ::Gitlab::Checks::ChangedBlobs.new(
            project, revisions, bytes_limit: BLOB_BYTES_LIMIT + 1, with_paths: true
          ).execute(timeout: timeout)
        end

        def skip_secret_detection?
          return true if changes_access.commits.any? do |commit|
            commit.safe_message =~ OLD_SPECIAL_COMMIT_FLAG ||
              commit.safe_message =~ NEW_SPECIAL_COMMIT_FLAG
          end

          return true if changes_access.push_options&.get(:secret_detection, :skip_all) ||
            changes_access.push_options&.get(:secret_push_protection, :skip_all)

          false
        end

        def revisions
          @revisions ||= changes_access
                           .changes
                           .pluck(:newrev) # rubocop:disable CodeReuse/ActiveRecord -- Array#pluck
                           .reject { |revision| ::Gitlab::Git.blank_ref?(revision) }
                           .compact
        end

        def format_git_guardian_response
          response = yield

          return unless response.present?

          message = response.join("\n") << remediation_message

          raise ::Gitlab::GitAccess::ForbiddenError, message
        rescue Gitlab::GitGuardian::Client::RequestError => e
          raise ::Gitlab::GitAccess::ForbiddenError, "GitGuardian API error: #{e.message}"
        end

        def remediation_message
          docs_url = ::Gitlab::Routing.url_helpers.help_page_url(
            'user/application_security/secret_detection/remove_secrets_tutorial.md',
            anchor: 'remove-the-secret-from-the-history'
          )

          format(REMEDIATION_MESSAGE, path: docs_url)
        end
      end
    end
  end
end
