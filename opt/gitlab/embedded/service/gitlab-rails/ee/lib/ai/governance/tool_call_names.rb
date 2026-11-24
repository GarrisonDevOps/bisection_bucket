# frozen_string_literal: true

module Ai
  module Governance
    # Names and classifies a recorded tool the way the Tool management tab does, so the
    # dashboard cards and that tab agree on what each tool is.
    class ToolCallNames
      def initialize(container)
        @container = container
        @resolved = {}
      end

      # Returns { tool_name:, governed:, action_type: }. A name no rule governs keeps the
      # recorded name, with the action type the MCP server declares for it, if any.
      def resolve(recorded_name)
        @resolved[recorded_name] ||= begin
          rule = ::Ai::ToolRules::Registry.governed_name_for(recorded_name, **catalogs)

          if rule
            { tool_name: rule, governed: true,
              action_type: ::Ai::ToolRules::Registry.action_type_of(rule, **catalogs) }
          else
            { tool_name: recorded_name, governed: false, action_type: served_action_type(recorded_name) }
          end
        end
      end

      private

      # A served tool with several catalog aliases has no single rule, but still declares
      # its own action type.
      def served_action_type(recorded_name)
        prefix = ::Ai::DuoWorkflows::McpConfigService::MCP_SERVER_TOOL_PREFIX
        return unless recorded_name.start_with?(prefix)

        mcp_tools.action_type_for(recorded_name.delete_prefix(prefix))
      end

      # Tool rules live on the root namespace, so tools are named for projects and
      # subgroups exactly as the Tool management tab names them.
      def mcp_tools
        @mcp_tools ||= ::Ai::ToolRules::GovernedMcpTools.for(@container.root_ancestor)
      end

      def catalogs
        @catalogs ||= {
          mcp_tools: mcp_tools,
          first_party_tools: ::Ai::ToolRules::FirstPartyTools.for(@container.root_ancestor)
        }
      end
    end
  end
end
