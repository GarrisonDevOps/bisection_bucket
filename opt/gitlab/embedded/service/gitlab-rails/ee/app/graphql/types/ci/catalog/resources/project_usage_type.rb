# frozen_string_literal: true

module Types
  module Ci
    module Catalog
      module Resources
        # rubocop: disable Graphql/AuthorizeTypes -- Authorization is handled in the resolver
        class ProjectUsageType < BaseObject
          graphql_name 'CiCatalogResourceProjectUsage'
          description 'A project that uses components from a catalog resource'

          field :project, ::Types::ProjectType, null: true,
            experiment: { milestone: '18.11' },
            description: 'Project using the components. Returns null if user cannot access the project.'

          field :components_used, [ComponentUsageDetailType], null: false,
            experiment: { milestone: '18.11' },
            description: 'List of components from the catalog resource used by the project.'
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
