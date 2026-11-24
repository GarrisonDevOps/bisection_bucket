# frozen_string_literal: true

module Ai
  module Catalog
    module Agents
      class UpdateService < Items::BaseUpdateService
        extend Gitlab::Utils::Override
        include Concerns::DwsAgentConfigValidator

        DEFINITION_ATTRIBUTES = %i[system_prompt tools mcp_tools mcp_servers user_prompt].freeze

        private

        override :validate_item
        def validate_item
          error('Agent not found') unless item && item.agent?
        end

        override :validate_before_save
        def validate_before_save
          return ServiceResponse.success unless item.latest_version.definition_changed?

          if ItemVersion.definition_too_large?(item.latest_version.definition)
            return error(ItemVersion.definition_size_error_message)
          end

          dws_result = validate_agent_config_with_dws(item.latest_version.definition)
          return error(dws_result.message) if dws_result.error?

          ServiceResponse.success
        end

        override :build_version_params
        def build_version_params(latest_version)
          definition_params = params.slice(*DEFINITION_ATTRIBUTES).stringify_keys
          return {} if definition_params.empty?

          if definition_params['tools'].present?
            new_tool_ids = definition_params['tools'].map!(&:id)
            old_tool_ids = old_definition['tools'] || []

            # If the tools are the same, but in a different order, it would be considered an update
            # and bump the version, which we don't want.
            definition_params['tools'] = old_tool_ids if new_tool_ids.to_set == old_tool_ids.to_set
          end

          if definition_params['mcp_tools'].present?
            new_mcp_tools = Array(definition_params['mcp_tools'])
            old_mcp_tools = old_definition['mcp_tools'] || []

            definition_params['mcp_tools'] =
              if new_mcp_tools.to_set == old_mcp_tools.to_set
                old_mcp_tools
              else
                new_mcp_tools
              end
          end

          if definition_params['mcp_servers'].present?
            new_mcp_server_ids = Array(definition_params['mcp_servers'])
            old_mcp_server_ids = old_definition['mcp_servers'] || []

            # If the MCP servers are the same, but in a different order, it would be considered an update
            # and bump the version, which we don't want.
            definition_params['mcp_servers'] =
              if new_mcp_server_ids.to_set == old_mcp_server_ids.to_set
                old_mcp_server_ids
              else
                new_mcp_server_ids
              end
          end

          {
            definition: latest_version.definition.merge(definition_params)
          }
        end

        override :save_item
        def save_item
          set_dws_validated_on_version(item.latest_version) if item.latest_version.definition_changed?
          item.save
        end

        override :latest_schema_version
        def latest_schema_version
          Ai::Catalog::ItemVersion::AGENT_SCHEMA_VERSION
        end

        override :track_update_audit_event
        def track_update_audit_event
          send_audit_events('update_ai_catalog_agent', item, { old_definition: old_definition })
        end
      end
    end
  end
end
