# frozen_string_literal: true

module Import
  module Sync
    module Github
      module Oauth
        # Creates and deletes the GitHub repository webhook for an OAuth-connected
        # repository. The caller supplies the OAuth-authenticated client and the
        # per-project callback URL.
        class WebhookManagementService
          include ::Gitlab::ExclusiveLeaseHelpers

          EVENTS = %w[
            push pull_request pull_request_review pull_request_review_comment issues issue_comment repository release
          ].freeze
          HOOK_DELETE_ERRORS = [Octokit::NotFound, Octokit::Unauthorized, Octokit::Forbidden].freeze
          LEASE_TTL = 5.minutes

          # The client must be parallel so a rate limit raises instead of sleeping
          # (possibly for an hour) while the lock is held.
          def initialize(repository, client:, callback_url:)
            raise ArgumentError, 'client must be parallel' unless client.parallel?

            @repository = repository
            @client = client
            @callback_url = callback_url
          end

          # Creates the webhook on GitHub and records its id and secret. Does
          # nothing if a webhook is already recorded.
          #
          # @raise [Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError] if another
          #   enable/disable is running for this repository
          # @return [void]
          def enable
            with_webhook_lock do
              next if repository.provider_webhook_xid.present?
              # A released, stopped or disconnected row must not get a hook nothing would remove.
              next unless repository.provisioning? || repository.provider_canonical?

              secret = SecureRandom.hex(32)
              hook = create_hook(secret)

              begin
                repository.update!(provider_webhook_xid: hook[:id], webhook_secret: secret)
              rescue StandardError
                # Without a local record, deliveries can't be verified, so don't leave the hook behind.
                delete_hook(hook[:id], ignored_errors: [StandardError])
                raise
              end

              repository.clear_auth_failures!
            end

            nil
          end

          # Deletes the webhook on GitHub and clears the local record. If the hook is
          # already gone or the token was revoked, the record is still cleared and the
          # user removes any leftover hook manually. Other errors, like a GitHub 5xx or
          # rate limit, are raised with the record kept, so the caller can retry.
          #
          # @raise [Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError] if another
          #   enable/disable is running for this repository
          # @return [void]
          def disable
            with_webhook_lock do
              next if repository.provider_webhook_xid.blank?

              delete_hook(repository.provider_webhook_xid)
              repository.update!(provider_webhook_xid: nil, webhook_secret: nil)
            end

            nil
          end

          private

          attr_reader :repository, :client, :callback_url

          # Reloads inside the lock so a record loaded before another process's
          # change can't create or delete a second hook.
          def with_webhook_lock
            in_lock("import_sync:repository:#{repository.id}:webhook", ttl: LEASE_TTL, retries: 0) do
              repository.reset
              yield
            end
          end

          # The numeric id keeps working if the repository is renamed or transferred.
          def github_repository_id
            repository.provider_repository_xid
          end

          # A 401 here means the OAuth token was revoked, since the client was
          # working when the caller obtained it moments earlier.
          def create_hook(secret)
            client.create_hook(
              github_repository_id,
              { url: callback_url, content_type: 'json', secret: secret },
              { events: EVENTS, active: true }
            )
          rescue Octokit::Unauthorized
            repository.record_auth_failure!
            raise
          end

          def delete_hook(hook_id, ignored_errors: HOOK_DELETE_ERRORS)
            client.delete_hook(github_repository_id, hook_id)
          rescue *ignored_errors => e
            ::Gitlab::GithubImport::Logger.warn(
              Labkit::Fields::LOG_MESSAGE => 'Failed to delete GitHub webhook',
              Labkit::Fields::GL_PROJECT_ID => repository.project_id,
              Labkit::Fields::ERROR_TYPE => e.class.name,
              'import_sync_repository_id' => repository.id
            )
          end
        end
      end
    end
  end
end
