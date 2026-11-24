# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class CreateService < Ai::Catalog::Items::BaseCreateService
        extend Gitlab::Utils::Override
        include Concerns::YamlDefinitionParser
        include Concerns::DwsFlowConfigValidator
        include Concerns::AgentReferences

        private

        override :allowed?
        def allowed?
          super && Ability.allowed?(current_user, :create_ai_catalog_flow, project)
        end

        override :item_type
        def item_type
          Ai::Catalog::Item::FLOW_TYPE
        end

        override :schema_version
        def schema_version
          Ai::Catalog::ItemVersion::FLOW_SCHEMA_VERSION
        end

        override :validate_before_save
        def validate_before_save
          return yaml_definition_error if yaml_definition_error

          references_error = agent_references_error
          return references_error if references_error

          dws_result = validate_flow_config_with_dws(definition_parsed)
          return error(dws_result.message) if dws_result.error?

          ServiceResponse.success
        end

        override :save_item
        def save_item(item)
          set_dws_validated_on_version(item.latest_version)

          save_with_agent_references(item) { super }
        end

        override :definition
        def definition
          definition_parsed
        end

        def flow_visibility
          params.fetch(:visibility) { Ai::Catalog::Item.column_defaults['visibility'] }
        end
      end
    end
  end
end
