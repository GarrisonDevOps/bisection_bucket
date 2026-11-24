# frozen_string_literal: true

module EE
  module API
    module Mcp
      module Handlers
        module ListTools
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          ASK_META = { 'anthropic/requiresUserInteraction' => true }.freeze

          prepended do
            include ::Gitlab::Utils::StrongMemoize
          end

          private

          override :governed_tool_data
          def governed_tool_data(tool_data, tool_name, current_user)
            return super unless ::Ai::ToolRules::McpGovernance.enabled_anywhere? && governed_namespace(current_user)

            governance = mcp_governance(current_user)
            return if governance.permission_for(tool_name.to_s) == ::Ai::ToolRules::Permissions::DENY
            return super unless governance.explicit_permission_for(tool_name.to_s) == ::Ai::ToolRules::Permissions::ASK

            super.deep_merge(_meta: ASK_META)
          end

          def governed_namespace(current_user)
            strong_memoize_with(:governed_namespace, current_user) do
              namespace = current_user&.governing_namespace
              namespace if namespace && ::Ai::ToolRules::McpGovernance.governs?(namespace)
            end
          end

          def mcp_governance(current_user)
            strong_memoize_with(:mcp_governance, current_user) do
              ::Ai::ToolRules::McpGovernance.new(
                governed_namespace(current_user),
                include_projects: false,
                surface: governance_surface(current_user)
              )
            end
          end

          def governance_surface(current_user)
            ::Ai::ToolRules::McpCallerSurface.for(context&.access_token, current_user)
          end
        end
      end
    end
  end
end
