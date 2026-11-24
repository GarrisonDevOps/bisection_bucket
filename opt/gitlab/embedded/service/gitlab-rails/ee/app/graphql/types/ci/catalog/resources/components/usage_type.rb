# frozen_string_literal: true

module Types
  module Ci
    module Catalog
      module Resources
        module Components
          # rubocop: disable Graphql/AuthorizeTypes -- We do not need authorization here as it is taken care of in ProjectUsageResolver.
          class UsageType < BaseObject
            graphql_name 'CiCatalogResourceComponentUsage'
            description 'Represents a component usage in a project'

            authorize_granular_token parent_authorizes: :read_ci_component_usage

            field :name, GraphQL::Types::String, null: true,
              description: 'Name of the component.'

            field :version, GraphQL::Types::String, null: true,
              description: 'Version of the component.'

            field :last_used_date, GraphQL::Types::ISO8601Date, null: true,
              description: 'When the component was last used.'

            def name
              BatchLoader::GraphQL.for(object.component_id).batch do |component_ids, loader|
                ::Ci::Catalog::Resources::Component.names_by_ids(component_ids).each do |component|
                  loader.call(component.id, component.name)
                end
              end
            end

            def version
              BatchLoader::GraphQL.for(object.component_id).batch do |component_ids, loader|
                ::Ci::Catalog::Resources::Component
                  .versions_by_component_ids(component_ids).each do |component|
                    loader.call(component.id, component.version_name)
                  end
              end
            end
          end
          # rubocop: enable Graphql/AuthorizeTypes
        end
      end
    end
  end
end
