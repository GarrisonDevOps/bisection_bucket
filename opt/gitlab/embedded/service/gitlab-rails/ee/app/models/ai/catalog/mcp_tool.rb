# frozen_string_literal: true

module Ai
  module Catalog
    # Represents an MCP tool dynamically discovered from Mcp::Tools::Manager.
    # Unlike BuiltInTool (which uses hardcoded ITEMS), this model computes
    # its items at boot time by querying the MCP tool registry.
    #
    # Tools are identified by their string `name` (stable across deployments)
    # rather than integer IDs (which are auto-generated and may shift).
    # Agent definitions store selected MCP tools as `mcp_tools: ["search", ...]`.
    class McpTool
      include ActiveRecord::FixedItemsModel::Model
      include GlobalID::Identification
      include ::Gitlab::Llm::Concerns::Logger

      DEFAULT_DESCRIPTION = "MCP tool"

      auto_generate_ids!

      attribute :name, :string
      attribute :title, :string
      attribute :description, :string
      attribute :unlisted, :boolean, default: false
      attribute :beta, :boolean, default: false

      validates :name, :title, presence: true

      class << self
        def fixed_items
          Gitlab::SafeRequestStore.fetch(:ai_catalog_mcp_tool_fixed_items) do
            manager = ::Mcp::Tools::Manager.new
            items = manager.list_tools.map do |tool_name, tool|
              {
                name: tool_name.to_s,
                title: humanize_tool_name(tool_name.to_s),
                description: extract_description(tool),
                unlisted: tool.try(:unlisted?) || false
              }
            end

            items + orbit_tools
          end
        end

        def find_by_name(name)
          find_by(name: name)
        end

        private

        # Orbit is still in beta (see doc/api/orbit.md), so its tools carry the
        # beta flag and the AI Catalog shows a Beta badge for them until Orbit is GA.
        def orbit_tools
          ::API::Orbit::McpHandlers::ToolCatalog::COMMAND_TOOL_NAMES.map do |name|
            {
              name: name,
              title: "Orbit: #{humanize_tool_name(name)}",
              description: "Orbit Knowledge Graph tool",
              beta: true
            }
          end
        end

        def humanize_tool_name(name)
          name.tr('_', ' ').split.map(&:capitalize).join(' ')
        end

        def extract_description(tool)
          desc = tool.respond_to?(:description) ? tool.description.to_s.truncate(500) : nil
          desc.presence || DEFAULT_DESCRIPTION
        rescue StandardError => e
          log_error(
            message: "Failed to extract MCP tool description",
            event_name: 'mcp_tool_description_extraction_error',
            ai_component: 'workflow_catalog',
            error: e.message,
            tool_name: tool.class.name.to_s
          )
          raise if Rails.env.development?

          DEFAULT_DESCRIPTION
        end
      end
    end
  end
end
