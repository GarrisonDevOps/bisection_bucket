# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ThirdPartyFlowVersionType < ::Types::BaseObject
        graphql_name 'AiCatalogThirdPartyFlowVersion'
        description 'An AI catalog third party flow version'
        authorize :read_ai_catalog_item
        authorize_granular_token permissions: :read_ai_catalog_item, boundary: :user, boundary_type: :user

        implements ::Types::Ai::Catalog::VersionInterface

        field :definition, GraphQL::Types::String, null: false, description: 'YAML definition of the third party flow.'

        def definition
          object.definition['yaml_definition'] || object.definition.to_yaml
        end
      end
    end
  end
end
