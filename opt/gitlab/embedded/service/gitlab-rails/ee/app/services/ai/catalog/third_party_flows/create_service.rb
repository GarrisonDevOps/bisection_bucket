# frozen_string_literal: true

module Ai
  module Catalog
    module ThirdPartyFlows
      class CreateService < Ai::Catalog::Items::BaseCreateService
        extend Gitlab::Utils::Override
        include Concerns::YamlDefinitionParser

        private

        override :allowed?
        def allowed?
          super && Ability.allowed?(current_user, :create_ai_catalog_third_party_flow, project)
        end

        override :item_type
        def item_type
          Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE
        end

        override :schema_version
        def schema_version
          Ai::Catalog::ItemVersion::THIRD_PARTY_FLOW_SCHEMA_VERSION
        end

        override :validate_before_save
        def validate_before_save
          return yaml_definition_error('ThirdPartyFlow') if yaml_definition_error('ThirdPartyFlow')

          ServiceResponse.success
        end

        override :definition
        def definition
          definition_parsed
        end
      end
    end
  end
end
