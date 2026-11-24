# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ItemConsumerType < ::Types::BaseObject
        graphql_name 'AiCatalogItemConsumer'
        description 'An AI catalog item configuration'
        authorize :read_ai_catalog_item_consumer
        authorize_granular_token permissions: :read_ai_catalog_item_consumer,
          boundaries: [
            { boundary: :project, boundary_type: :project },
            { boundary: :group, boundary_type: :group }
          ]

        connection_type_class ::Types::CountableConnectionType

        expose_permissions ::Types::PermissionTypes::Ai::Catalog::ItemConsumer

        PATH_HELPERS = {
          group: {
            agent: ->(container, id) { helpers.group_automate_agent_path(container, id: id) },
            third_party_flow: ->(container, id) { helpers.group_automate_agent_path(container, id: id) },
            flow: ->(container, id) { helpers.group_automate_flow_path(container, id: id) }
          },
          project: {
            agent: ->(container, id) { helpers.project_automate_agent_path(container, id: id) },
            third_party_flow: ->(container, id) { helpers.project_automate_agent_path(container, id: id) },
            flow: ->(container, id) { helpers.project_automate_flow_path(container, id: id) }
          }
        }.freeze

        field :consumer_kind, ::Types::Ai::Catalog::ItemConsumerKindEnum,
          null: false,
          method: :kind,
          description: 'Type of configured catalog item.'
        field :enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates if the configuration item is enabled.'
        field :flow_trigger, ::Types::Ai::FlowTriggerType,
          null: true,
          deprecated: { reason: 'Use `flowTriggers`', milestone: '19.4' },
          description: 'Trigger associated with the configured catalog item.'
        field :flow_triggers, [::Types::Ai::FlowTriggerType], # rubocop:disable GraphQL/ExtractType -- transient pair; flowTrigger is deprecated and removed once the frontend migrates
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Triggers associated with the configured catalog item.'
        field :group, ::Types::GroupType,
          null: true,
          description: 'Group in which the catalog item is configured.'
        field :id, GraphQL::Types::ID,
          null: false,
          description: 'ID of the configuration item.'
        field :item, ::Types::Ai::Catalog::ItemInterface,
          null: true,
          description: 'Configuration catalog item.'
        field :organization, ::Types::Organizations::OrganizationType,
          null: true,
          description: 'Organization in which the catalog item is configured.'
        field :parent_item_consumer, ::Types::Ai::Catalog::ItemConsumerType,
          null: true,
          description: 'Parent item consumer associated with the configured catalog item.'
        field :pinned_item_version, ::Types::Ai::Catalog::VersionInterface,
          null: true,
          description: 'Resolved item version according to the `pinnedVersionPrefix`.' \
            'This field can only be resolved for 20 AiCatalogItemConsumers in any single request.' do
          extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 20)
        end
        field :pinned_version_prefix, ::Types::Ai::Catalog::PinnedVersionType, # rubocop:disable GraphQL/ExtractType -- Not sensible to create a "pinned" type
          null: true,
          description: 'Version the item is pinned to, in the format `n.n.n`.'
        field :project, ::Types::ProjectType,
          null: true,
          description: 'Project in which the catalog item is configured.'
        field :service_account, ::Types::UserType,
          null: true,
          description: 'Service account associated with the item consumer.'
        field :web_path, GraphQL::Types::String,
          null: true,
          description: 'Web path of the catalog item consumer configuration page.'

        def self.helpers
          ::Gitlab::Routing.url_helpers
        end

        def self.authorized?(object, context)
          super(object.authorization_subject(project: context[:ai_catalog_authorizing_project]), context)
        end

        # Clears the project for child fields, so nested item consumers are not checked against it.
        def initialize(object, context)
          super

          @authorizing_project = context[:ai_catalog_authorizing_project]
          context.scoped_set!(:ai_catalog_authorizing_project, nil)
        end

        # Overrides `expose_permissions`' `method: :itself` so permissions use the same subject as `authorized?`.
        def user_permissions
          object.authorization_subject(project: @authorizing_project)
        end

        def item
          preloads = [:organization, { project: [:route, :namespace, :group, :project_namespace] }]

          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Ai::Catalog::Item, object.ai_catalog_item_id, preloads)
            .find
        end

        def parent_item_consumer
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Ai::Catalog::ItemConsumer, object.parent_item_consumer_id)
            .find
        end

        def pinned_item_version
          item = object.item

          item&.resolve_version(object.pinned_version_prefix)&.tap { |version| version.item = item }
        end

        def service_account
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(User, object.service_account_id).find
        end

        def flow_trigger
          BatchLoader::GraphQL.for(object.id).batch do |item_consumer_ids, loader|
            ::Ai::FlowTrigger.by_item_consumer_ids(item_consumer_ids).each do |trigger|
              loader.call(trigger.ai_catalog_item_consumer_id, trigger)
            end
          end
        end

        def flow_triggers
          BatchLoader::GraphQL.for(object.id).batch(default_value: []) do |item_consumer_ids, loader|
            triggers_by_consumer = ::Ai::FlowTrigger.by_item_consumer_ids(item_consumer_ids)
              .ordered_by_id
              .group_by(&:ai_catalog_item_consumer_id)

            item_consumer_ids.each do |id|
              loader.call(id, triggers_by_consumer.fetch(id, []))
            end
          end
        end

        def web_path
          Gitlab::Graphql::Lazy.with_value(item) { |resolved_item| item_consumer_path(resolved_item) if resolved_item }
        end

        private

        def item_consumer_path(item)
          container_type, container = if object.group
                                        [:group, object.group]
                                      elsif object.project
                                        [:project, object.project]
                                      end

          return unless container_type

          path_helper = PATH_HELPERS.dig(container_type, item.item_type.to_sym)
          return unless path_helper

          path_helper.call(container, item.id)
        end
      end
    end
  end
end
