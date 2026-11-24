# frozen_string_literal: true

module Gitlab
  module Auth
    module RemoteDevelopment
      module AuthFinders
        extend ActiveSupport::Concern

        included do
          # @return [RemoteDevelopment::WorkspaceToken]
          def workspace_token_from_authorization_token
            # NOTE: "workspace_token_string" is the JWT token from KAS, because agentw requests are proxied through KAS
            workspace_token_string = current_request.headers[Gitlab::Kas::INTERNAL_API_AGENT_REQUEST_HEADER]

            return unless workspace_token_string.present?

            ::RemoteDevelopment::WorkspaceToken.find_by_token(workspace_token_string)
          end
        end
      end
    end
  end
end
