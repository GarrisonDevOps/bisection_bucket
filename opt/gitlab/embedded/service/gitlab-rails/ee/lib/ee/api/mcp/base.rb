# frozen_string_literal: true

module EE
  module API
    module Mcp
      module Base
        extend ActiveSupport::Concern

        prepended do
          helpers ::API::Orbit::QueryResponseHelpers

          helpers do
            extend ::Gitlab::Utils::Override
            include ::Gitlab::Utils::StrongMemoize

            override :mcp_denial_reason
            def mcp_denial_reason
              # On SaaS the instance setting does not gate access; the namespace-level
              # check is the authority.
              if ::Gitlab::Saas.feature_available?(:mcp_server_saas_only)
                authorizer = ::Ai::UserAuthorizer.for(current_user)
                return :no_enabled_namespace unless authorizer.any_group_with_mcp_server_enabled?

                nil
              else
                super
              end
            end
            strong_memoize_attr :mcp_denial_reason

            override :mcp_denial_message
            def mcp_denial_message
              return 'MCP server not enabled for any of your groups' if mcp_denial_reason == :no_enabled_namespace

              super
            end

            override :render_mcp_result
            def render_mcp_result(result)
              return super unless result.is_a?(::Analytics::Orbit::CommandInterceptor::OrbitQuery)

              render_orbit_response!(result.response)
            end
          end
        end
      end
    end
  end
end
