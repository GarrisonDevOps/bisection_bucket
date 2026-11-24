# frozen_string_literal: true

module Ai
  module Catalog
    module Agents
      class AuditEventMessageService < Items::BaseAuditEventMessageService
        TOOLS_ID_AND_NAME = Ai::Catalog::BuiltInTool::ITEMS.to_h { |item| [item[:id], item[:name]] }.freeze

        private

        def item_type
          'agent'
        end

        def expected_schema_version
          1 # AGENT_SCHEMA_VERSION - Update this when Ai::Catalog::ItemVersion::AGENT_SCHEMA_VERSION changes
        end

        def create_messages
          messages = []

          tools = item.latest_version.definition['tools'] || []

          if tools.present?
            tools_list = format_tools_list(tools)
            messages << "Created a new #{visibility_label} AI agent with tools: #{tools_list}"
          else
            messages << "Created a new #{visibility_label} AI agent with no tools"
          end

          messages << version_message(item.latest_version)

          messages
        end

        def build_change_descriptions
          descriptions = []

          old_def, new_def = get_definition_comparison
          return descriptions unless old_def && new_def

          old_tools = old_def['tools'] || []
          new_tools = new_def['tools'] || []
          tools_added = new_tools - old_tools
          tools_removed = old_tools - new_tools

          if tools_added.any?
            tools_list = format_tools_list(tools_added)
            descriptions << "Added tools: #{tools_list}"
          end

          if tools_removed.any?
            tools_list = format_tools_list(tools_removed)
            descriptions << "Removed tools: #{tools_list}"
          end

          descriptions << 'Changed system prompt' if old_def['system_prompt']&.strip != new_def['system_prompt']&.strip

          descriptions
        end

        def format_tools_list(tools)
          return '[]' if tools.blank?

          tool_names = tools.filter_map { |tool_id| TOOLS_ID_AND_NAME[tool_id] }

          "[#{tool_names.join(', ')}]"
        end
      end
    end
  end
end
