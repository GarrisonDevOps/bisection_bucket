# frozen_string_literal: true

module EE
  module Types
    module Ci
      module Catalog
        module ResourceType
          extend ActiveSupport::Concern

          prepended do
            field :project_component_usages,
              ::Types::Ci::Catalog::Resources::ProjectUsageType.connection_type,
              null: true,
              experiment: { milestone: '18.11' },
              description: 'Projects using components from this catalog resource. ' \
                'Only available to maintainers of the catalog resource project. ' \
                'This field can only be resolved for one catalog resource in any single request.',
              resolver: ::Resolvers::Ci::Catalog::Resources::ProjectComponentUsagesResolver do
              extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
            end
          end
        end
      end
    end
  end
end
