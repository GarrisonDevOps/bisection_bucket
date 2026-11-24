# frozen_string_literal: true

module EE
  module Gitlab
    module Mcp
      module Administration
        module VerifyMcpServerSetup
          extend ::Gitlab::Utils::Override

          override :check_mcp_server_enabled
          def check_mcp_server_enabled
            if ::Gitlab::Saas.feature_available?(:mcp_server_saas_only)
              return record(:mcp_server_enabled,
                status: :info,
                message: "mcp_server_enabled: not applicable (SaaS)",
                detail: "On GitLab.com, MCP server availability is controlled per top-level group " \
                  "(Group > Settings > General > Permissions > Enable MCP server), not by an instance " \
                  "setting. See the user-specific check below.")
            end

            super
          end

          override :check_user
          def check_user(user)
            super

            check_user_namespace_mcp_server_enabled(user)
          end

          private

          def check_user_namespace_mcp_server_enabled(user)
            return unless ::Gitlab::Saas.feature_available?(:mcp_server_saas_only)

            if ::Ai::UserAuthorizer.for(user).any_group_with_mcp_server_enabled?
              record(:user_namespace_mcp_server_enabled,
                status: :pass,
                message: "@#{user.username} belongs to a group with MCP server enabled.",
                detail: "On SaaS, the MCP server checks namespace-level mcp_server_enabled " \
                  "via any_group_with_mcp_server_enabled? instead of the instance-level setting.")
            else
              record(:user_namespace_mcp_server_enabled,
                status: :fail,
                message: "@#{user.username} does NOT belong to any group with MCP server enabled.",
                detail: "On SaaS, the MCP server requires the user to be a member of at least one " \
                  "top-level group with MCP server enabled. " \
                  "Ask a group owner to enable it in group settings.")
            end
          end
        end
      end
    end
  end
end
