# frozen_string_literal: true

module Ai
  module Catalog
    module Agents
      class CreateService < Ai::Catalog::Items::BaseCreateService
        extend Gitlab::Utils::Override
        include Concerns::DwsAgentConfigValidator

        private

        override :allowed?
        def allowed?
          super && Ability.allowed?(current_user, :create_ai_catalog_agent, project)
        end

        override :item_type
        def item_type
          Ai::Catalog::Item::AGENT_TYPE
        end

        override :schema_version
        def schema_version
          Ai::Catalog::ItemVersion::AGENT_SCHEMA_VERSION
        end

        override :validate_before_save
        def validate_before_save
          return error(ItemVersion.definition_size_error_message) if ItemVersion.definition_too_large?(definition)

          dws_result = validate_agent_config_with_dws(definition)
          return error(dws_result.message) if dws_result.error?

          ServiceResponse.success
        end

        override :save_item
        def save_item(item)
          set_dws_validated_on_version(item.latest_version)
          super
        end

        override :definition
        def definition
          {
            tools: Array(params[:tools]).map(&:id),
            mcp_tools: Array(params[:mcp_tools]),
            mcp_servers: Array(params[:mcp_servers]),
            system_prompt: params[:system_prompt],
            user_prompt: params[:user_prompt] || ""
          }
        end
      end
    end
  end
end
