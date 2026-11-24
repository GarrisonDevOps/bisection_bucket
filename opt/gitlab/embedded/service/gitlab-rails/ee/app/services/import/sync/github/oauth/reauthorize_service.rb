# frozen_string_literal: true

module Import
  module Sync
    module Github
      module Oauth
        # Restores a disconnected, OAuth-connected repository after the user
        # re-authorizes GitHub, and re-creates the webhook if it is missing. The
        # caller supplies a fresh OAuth-authenticated client from that re-authorization.
        class ReauthorizeService
          include ::Gitlab::Utils::Executable

          def initialize(repository, client:, callback_url:)
            @repository = repository
            @client = client
            @callback_url = callback_url
          end

          # @return [ServiceResponse]
          def execute
            return ServiceResponse.error(message: 'Repository is not disconnected') unless repository.disconnected?
            return account_mismatch_response unless reauthorized_account_matches?

            disconnect_reason = repository.disconnect_reason
            restore_to = repository.restore_authority_state

            repository.restore!
            WebhookManagementService.new(repository, client: client, callback_url: callback_url).enable

            ServiceResponse.success
          rescue Octokit::Error => e
            # Leaves the repository ready for another re-authorization attempt, rather than
            # stuck "connected" with no working webhook and no way back into this service.
            repository.disconnect!(disconnect_reason, restore_to: restore_to) unless repository.disconnected?
            ServiceResponse.error(message: e.message, reason: :provider_error)
          end

          private

          attr_reader :repository, :client, :callback_url

          # Without this check, a token for a different GitHub account could
          # restore someone else's repository connection. Client#user fetches a
          # user by login, so this goes through Octokit directly to get the
          # authenticated account.
          def reauthorized_account_matches?
            client.octokit.user.to_h[:id] == repository.provider_account_xid
          end

          def account_mismatch_response
            ServiceResponse.error(message: 'GitHub account does not match', reason: :account_mismatch)
          end
        end
      end
    end
  end
end
