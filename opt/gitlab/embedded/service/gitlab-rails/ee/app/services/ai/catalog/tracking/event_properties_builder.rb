# frozen_string_literal: true

module Ai
  module Catalog
    module Tracking
      # Builds the AI Catalog event properties hash for internal events.
      class EventPropertiesBuilder
        include Concerns::FlowDefinitionToolExtractor

        UnhandledItemType = Class.new(ArgumentError)

        LIST_SEPARATOR = ','

        # @param item [Ai::Catalog::Item] required
        # @param version [Ai::Catalog::ItemVersion] required
        # @raise [ArgumentError] if item or version is nil
        def initialize(item:, version:)
          raise ArgumentError, 'item is required' if item.nil?
          raise ArgumentError, 'version is required' if version.nil?

          @item = item
          @version = version
          @item_type = find_item_type
        end

        # @return [Hash] properties hash with nil values removed
        def to_h
          unless item_type
            flag_unhandled_type!
            return {}
          end

          {
            item_type: item_type,
            item_version: item_version,
            item_schema_version: item_schema_version,
            flow_name: foundational_flow_name,
            custom_item_id: custom_item_id,
            tools: tools,
            mcp_tools: mcp_tools,
            mcp_servers: mcp_servers,
            components: components
          }.compact

        rescue StandardError => error
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
            error,
            item_id: item.try(:id),
            item_version_id: version.try(:id),
            item_type: item_type
          )

          {}
        end

        private

        attr_reader :item, :item_type, :version

        def find_item_type
          return 'foundational_flow' if item.foundational_flow?
          return 'foundational_external_agent' if item.foundational_third_party_flow?
          return 'custom_flow' if item.custom_flow?
          return 'custom_external_agent' if item.custom_third_party_flow?
          return 'custom_skill' if item.skill?

          'custom_agent' if item.custom_agent?
        end

        # Item version (e.g. "1.1.0")
        def item_version
          if item.foundational_flow?
            item.foundational_flow&.flow_version
          else
            version.version
          end
        end

        # Flow Schema version (e.g. "v1").
        def item_schema_version
          if item.foundational_flow?
            foundational_flow_reference_parts&.last
          elsif item.custom_flow?
            version.def_version
          elsif item.custom_agent?
            DuoWorkflowPayloadBuilder::V1::FLOW_VERSION
          end
        end

        def foundational_flow_name
          return unless item.foundational_flow?

          foundational_flow_reference_parts&.first
        end

        # Returns the ai_catalog_items.id for any item that has a row in
        # that table. This includes custom items AND foundational external
        # agents (foundational flows are identified through foundational_flow_name).
        def custom_item_id
          return if item.foundational_flow?

          item.id
        end

        # Tool names (e.g. ["get_issue"])
        def tools
          if item.custom_agent?
            # rubocop:disable CodeReuse/ActiveRecord -- BuiltInTool is a FixedItemsModel, not a real ActiveRecord model
            join_list(Ai::Catalog::BuiltInTool.where(id: version.def_tools).map(&:name))
            # rubocop:enable CodeReuse/ActiveRecord
          elsif item.custom_flow?
            tool_names = extract_tools_from_flow_definition(version.definition)

            join_list(tool_names)
          end
        end

        # MCP tool names (e.g. ["search"])
        def mcp_tools
          return unless item.custom_agent?

          join_list(version.def_mcp_tools)
        end

        # MCP server IDs (e.g., [1])
        def mcp_servers
          return unless item.custom_agent?

          join_list(version.def_mcp_servers)
        end

        # Flow component names (e.g. ["AgentComponent"])
        def components
          return unless item.custom_flow?

          component_types = Array(version.def_components).filter_map { |c| c['type'] }

          join_list(component_types)
        end

        def join_list(list)
          return if list.blank?

          list.join(LIST_SEPARATOR)
        end

        def flag_unhandled_type!
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
            UnhandledItemType.new,
            item_id: item.try(:id), item_type: item.try(:item_type)
          )
        end

        def foundational_flow_reference_parts
          return unless item.foundational_flow?

          @foundational_flow_reference_parts ||= item.foundational_flow_reference.to_s.split('/', 2).map(&:presence)
        end
      end
    end
  end
end
