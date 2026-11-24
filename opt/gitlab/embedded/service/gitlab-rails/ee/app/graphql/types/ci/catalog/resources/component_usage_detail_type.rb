# frozen_string_literal: true

module Types
  module Ci
    module Catalog
      module Resources
        # rubocop: disable Graphql/AuthorizeTypes -- Authorization is handled in the resolver
        class ComponentUsageDetailType < BaseObject
          graphql_name 'CiCatalogResourceComponentUsageDetail'
          description "Details of a project's usage of a component from a catalog resource."

          field :component, ::Types::Ci::Catalog::Resources::ComponentType, null: false,
            experiment: { milestone: '18.11' },
            description: 'Component being used.'

          field :version, ::Types::Ci::Catalog::Resources::VersionType, null: true,
            experiment: { milestone: '18.11' },
            description: 'Version of the component being used.'

          field :last_used_date, GraphQL::Types::ISO8601Date, null: false,
            experiment: { milestone: '18.11' },
            description: 'Date when the component was last used by the project.'

          field :outdated, GraphQL::Types::Boolean, null: false,
            experiment: { milestone: '18.11' },
            description: 'Whether the project is using a component version older than the ' \
              'catalog resource latest version.'
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
