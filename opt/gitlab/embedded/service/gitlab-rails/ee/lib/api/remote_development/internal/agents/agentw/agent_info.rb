# frozen_string_literal: true

module API
  module RemoteDevelopment
    module Internal
      module Agents
        module Agentw
          class AgentInfo < ::API::Base
            helpers ::API::Helpers::KasHelpers

            before do
              authenticate_gitlab_kas_request!
            end

            namespace "internal" do
              namespace "agents" do
                namespace "agentw" do
                  desc "Gets agentw info" do
                    detail "Retrieves agent info for agentw for the given workspace token"
                    tags %w[workspaces internal_operations]
                    success code: 200, message: "Agentw info retrieved successfully"
                    failure [
                      { code: 401, message: 'Unauthorized' }
                    ]
                  end

                  route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                  get '/agent_info', feature_category: :workspaces, urgency: :low do
                    workspace_token = workspace_token_from_authorization_token

                    unauthorized! unless workspace_token

                    status 200

                    {
                      workspace_id: workspace_token.workspace.id
                    }
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end
