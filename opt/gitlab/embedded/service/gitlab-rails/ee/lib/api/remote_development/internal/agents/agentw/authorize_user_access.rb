# frozen_string_literal: true

module API
  module RemoteDevelopment
    module Internal
      module Agents
        module Agentw
          class AuthorizeUserAccess < ::API::Base
            before do
              authenticate_gitlab_kas_request!
            end

            helpers ::API::Helpers::KasHelpers

            namespace "internal" do
              namespace "agents" do
                namespace "agentw" do
                  desc "authorize_user_access" do
                    detail "Returns whether the user is authorized to access the workspace."
                    tags %w[workspaces internal_operations]
                    success code: 200, message: "User access authorization info retrieved successfully"
                  end
                  params do
                    requires :workspace_host, type: String, desc: 'Host of the workspace being accessed.'
                    requires :user_id, type: Integer, desc: 'ID of the user accessing the workspace.'
                  end
                  route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                  get "/authorize_user_access", feature_category: :workspaces, urgency: :low do
                    response = ::RemoteDevelopment::CommonService.execute(
                      domain_main_class: ::RemoteDevelopment::WorkspacesServerOperations::AuthorizeUserAccess::Main,
                      domain_main_class_args: {
                        workspace_host: params[:workspace_host],
                        user_id: params[:user_id]
                      }
                    )

                    # NOTE: There's currently no way an error can be returned other than an unexpected raised
                    #       exception, so we assume success.
                    status 200

                    response.payload
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
