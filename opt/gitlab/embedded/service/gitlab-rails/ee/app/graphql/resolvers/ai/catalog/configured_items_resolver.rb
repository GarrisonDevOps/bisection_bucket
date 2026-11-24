# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class ConfiguredItemsResolver < BaseResolver
        description 'Find AI Catalog items configured for use.'

        type ::Types::Ai::Catalog::ItemConsumerType.connection_type, null: false

        before_connection_authorization do |consumers, _current_user|
          ::Ai::Catalog::Preloaders::ItemConsumerPolicyPreloader.new(consumers.to_a).execute
        end

        argument :group_id,
          ::Types::GlobalIDType[::Group],
          prepare: ->(global_id, _ctx) { global_id&.model_id },
          required: false,
          description: 'Group ID to retrieve configured AI Catalog items for.'

        argument :include_inherited,
          GraphQL::Types::Boolean,
          required: false,
          description: "Include configured AI Catalog items inherited from the project's top-level group. " \
            'Can only be used with `projectId`.'

        argument :include_foundational_consumers,
          GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          description: 'Include configured foundational AI Catalog items.',
          experiment: { milestone: '18.10' }

        argument :item_id,
          ::Types::GlobalIDType[::Ai::Catalog::Item],
          prepare: ->(global_id, _ctx) { global_id&.model_id },
          required: false,
          description: 'Item ID to retrieve configured AI Catalog items for.'

        argument :project_id,
          ::Types::GlobalIDType[::Project],
          prepare: ->(global_id, _ctx) { global_id&.model_id },
          required: false,
          description: 'Project ID to retrieve configured AI Catalog items for.'

        argument :configurable_for_project_id,
          ::Types::GlobalIDType[::Project],
          prepare: ->(global_id, _ctx) { global_id&.model_id },
          required: false,
          description: 'Project ID to filter AI Catalog item consumers. When provided with group_id, returns only ' \
            'consumers whose associated items are configurable within the project (i.e., group-enabled ' \
            'items that are public or owned by the project). Excludes consumers for items that are ' \
            'private to other projects.'

        argument :foundational_flow_reference,
          GraphQL::Types::String,
          required: false,
          description: 'Filter by foundational flow reference.'

        argument :item_type, ::Types::Ai::Catalog::ItemTypeEnum,
          required: false,
          description: 'Type of items to retrieve.'

        argument :item_types, [::Types::Ai::Catalog::ItemTypeEnum],
          required: false,
          description: 'Types of items to retrieve.'

        argument :sort, ::Types::Ai::Catalog::ConfiguredItemsSortEnum,
          required: false,
          description: 'Sort configured items, for example by usage.'

        validates at_least_one_of: [:group_id, :project_id]

        def ready?(**args)
          if args[:include_inherited] && args[:project_id].nil?
            raise Gitlab::Graphql::Errors::ArgumentError, '`includeInherited` can only be used with `projectId`.'
          end

          super
        end

        def resolve(**args)
          finder = ::Ai::Catalog::ItemConsumersFinder.new(current_user, params: args)
          consumers = finder.execute.with_items_and_latest_versions

          context.scoped_set!(:ai_catalog_authorizing_project, finder.container) if args[:project_id]

          consumers
        end
      end
    end
  end
end
