# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      module ItemInterface
        include Types::BaseInterface
        prepend Gitlab::Graphql::ExposePermissions
        prepend Gitlab::Graphql::MarkdownField

        RESOLVE_TYPES = {
          ::Ai::Catalog::Item::AGENT_TYPE => ::Types::Ai::Catalog::AgentType,
          ::Ai::Catalog::Item::FLOW_TYPE => ::Types::Ai::Catalog::FlowType,
          ::Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE => ::Types::Ai::Catalog::ThirdPartyFlowType,
          ::Ai::Catalog::Item::SKILL_TYPE => ::Types::Ai::Catalog::SkillType
        }.freeze

        graphql_name 'AiCatalogItem'
        description 'An AI catalog item'

        connection_type_class ::Types::CountableConnectionType

        expose_permissions ::Types::PermissionTypes::Ai::Catalog::Item

        field :created_at, ::Types::TimeType, null: false, description: 'Timestamp of when the item was created.'
        field :updated_at, ::Types::TimeType, null: false, description: 'Timestamp of when the item was updated.'
        field :soft_deleted_at, ::Types::TimeType, method: :deleted_at, null: true,
          description: 'Timestamp of when the item was soft deleted.'
        field :soft_deleted, GraphQL::Types::Boolean, method: :deleted?, null: true,
          description: 'Indicates if the item has been soft deleted.'
        field :description, GraphQL::Types::String, null: false, description: 'Description of the item.'
        field :id, GraphQL::Types::ID, null: false, description: 'ID of the item.'
        field :item_type,
          ItemTypeEnum,
          null: false,
          description: 'Type of the item.'
        field :name, GraphQL::Types::String, null: false, description: 'Name of the item.'
        field :project, ::Types::ProjectType, null: true, description: 'Project for the item.'
        field :public, GraphQL::Types::Boolean,
          null: false,
          method: :visibility_public?,
          deprecated: { reason: 'Use `visibility`', milestone: '19.3' },
          description: 'Whether the item is publicly visible in the catalog.'
        field :visibility, ItemVisibilityEnum,
          null: false,
          experiment: { milestone: '19.2' },
          description: 'Visibility of the item in the catalog.'
        field :versions, ::Types::Ai::Catalog::VersionInterface.connection_type,
          null: true,
          max_page_size: 20,
          description: 'Versions of the item. ' \
            'This field can only be resolved for one AiCatalogItem in any single request.' do
          extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 1)
        end
        field :latest_version, ::Types::Ai::Catalog::VersionInterface,
          null: true,
          description: 'Latest version of the item.' do
            argument :released, ::GraphQL::Types::Boolean, required: false,
              description: 'Return the latest released version.'
          end
        field :configuration_for_project, ::Types::Ai::Catalog::ItemConsumerType,
          null: true,
          experiment: { milestone: '18.6' },
          description: 'Item configuration for the given project.' do
          argument :project_id, ::Types::GlobalIDType[::Project], required: true,
            description: 'Global ID of the project to return the item configuration of.'
        end
        field :configuration_for_group, ::Types::Ai::Catalog::ItemConsumerType,
          null: true,
          experiment: { milestone: '18.7' },
          description: 'Item configuration for the given group.' do
          argument :group_id, ::Types::GlobalIDType[::Group], required: true,
            description: 'Global ID of the group to return the item configuration of.'
        end
        field :foundational,
          GraphQL::Types::Boolean,
          null: false,
          method: :foundational?,
          description: 'Whether the item is a foundational item.'
        field :foundational_flow_reference, GraphQL::Types::String,
          null: true,
          description: 'Foundational flow reference.'
        field :last_30_day_usage_count, GraphQL::Types::Int,
          null: false,
          description: 'Number of projects using the item in the last 30 days.'
        field :star_count, GraphQL::Types::Int,
          null: false,
          description: 'Number of stars for the item.'
        field :starred, GraphQL::Types::Boolean,
          null: false,
          description: 'Whether the current user has starred the item.'
        field :verification_level, Types::Ai::Catalog::ItemVerificationLevelEnum, null: false,
          description: 'Verification level of the item.'
        field :is_enabled_in_managed_by_project, GraphQL::Types::Boolean,
          null: false,
          method: :enabled_in_managed_by_project?,
          description: 'Whether the item is enabled in the project it is managed by. ' \
            'This field can only be resolved for one AiCatalogItem in any single request.' do
          extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 1)
        end
        field :has_direct_project_configurations_in_group, GraphQL::Types::Boolean,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Whether any project in the group has its own configuration of the item. ' \
            'Returns `null` when the user cannot enable items for the group, or the group is not a top-level group. ' \
            'This field can only be resolved for one AiCatalogItem in any single request.' do
          argument :group_id, ::Types::GlobalIDType[::Group], required: true,
            description: 'Global ID of the group.'
          extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: 1)
        end
        field :effective_version, ::Types::Ai::Catalog::VersionInterface,
          null: true,
          experiment: { milestone: '19.3' },
          description: 'Version of the item in effect for the given namespace, falling back to ' \
            'the latest version when none is in effect. In a project ' \
            'namespace, resolves to the project configuration pinned version when enabled, ' \
            'otherwise the latest version. In a group namespace, resolves to the group ' \
            'configuration pinned version when enabled, otherwise the latest version. In the ' \
            'global namespace, always resolves to the latest version.' do
          argument :project_id, ::Types::GlobalIDType[::Project], required: false,
            description: 'Global ID of the project to return the effective version for.'
          argument :group_id, ::Types::GlobalIDType[::Group], required: false,
            description: 'Global ID of the group to return the effective version for.'
          validates mutually_exclusive: [:project_id, :group_id]
        end

        field :web_path, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Web path of the item in the AI catalog.'

        markdown_field :description_html, null: true

        # Restrict Markdown rendering to GitLab-managed (foundational) items.
        # Custom user-supplied items return nil; consumers fall back to plain `description`.
        def description_html_resolver
          return unless object.foundational?

          ::MarkupHelper.markdown_field(object, :description, context.to_h.dup)
        end

        def verification_level
          return object.verification_level unless object.foundational_chat_agent?

          definition = ::Ai::FoundationalChatAgent.for_catalog_item(object.id)
          ::Ai::Catalog::Item.verification_levels.key(definition.verification_level)
        end

        orphan_types ::Types::Ai::Catalog::AgentType
        orphan_types ::Types::Ai::Catalog::FlowType
        orphan_types ::Types::Ai::Catalog::ThirdPartyFlowType
        orphan_types ::Types::Ai::Catalog::SkillType

        def project
          Gitlab::Graphql::Lazy.with_value(policy_loaded_item, &:project)
        end

        def starred
          return false unless current_user

          BatchLoader::GraphQL.for(object.id).batch(key: current_user.id) do |item_ids, loader, args|
            starred_ids = ::Ai::Catalog::ItemStar.starred_item_ids_for_user(args[:key], item_ids)

            item_ids.each { |id| loader.call(id, starred_ids.include?(id)) }
          end
        end

        def latest_version(released: nil)
          version_id = released ? object.latest_released_version_id : object.latest_version_id
          return unless version_id

          lazy_version = Gitlab::Graphql::Loaders::BatchModelLoader.new(
            ::Ai::Catalog::ItemVersion,
            version_id
          ).find

          # `ItemVersion#item` is needed for `VersionInterface.resolve_type` and authorization checks.
          # After batch loading, set the association in place to avoid further loading of `Item` records.
          Gitlab::Graphql::Lazy.with_value(lazy_version) do |version|
            version.tap { |v| v.item = object }
          end
        end

        def configuration_for_project(project_id:)
          BatchLoader::GraphQL.for([project_id.model_id.to_i, object.id]).batch do |container_item_pairs, loader|
            load_item_consumer_configuration(
              container_item_pairs: container_item_pairs,
              loader: loader,
              container_type: :project
            )
          end
        end

        def has_direct_project_configurations_in_group(group_id:) # rubocop:disable Naming/PredicatePrefix -- GraphQL field resolver, not a Ruby predicate
          group = GitlabSchema.find_by_gid(group_id).sync
          return unless group && group.root? && Ability.allowed?(current_user, :create_ai_catalog_item_consumer, group)

          object.direct_project_configurations_in_group?(group)
        end

        def configuration_for_group(group_id:)
          BatchLoader::GraphQL.for([group_id.model_id.to_i, object.id]).batch do |container_item_pairs, loader|
            load_item_consumer_configuration(
              container_item_pairs: container_item_pairs,
              loader: loader,
              container_type: :group
            )
          end
        end

        def web_path
          ::Gitlab::UrlBuilder.ai_catalog_item_url(object, only_path: true)
        end

        def effective_version(project_id: nil, group_id: nil)
          return version_by_id(object.latest_version_id) unless project_id || group_id

          lazy_consumer = if project_id
                            configuration_for_project(project_id: project_id)
                          else
                            configuration_for_group(group_id: group_id)
                          end

          ::Ai::Catalog::EffectiveVersionBatchLoader.load_for(object, lazy_consumer, current_user)
        end

        private

        def policy_loaded_item
          ::Gitlab::Graphql::Loaders::Ai::Catalog::ItemWithProjectLoader.new(object, current_user).find
        end

        def version_by_id(version_id)
          return unless version_id

          with_item(Gitlab::Graphql::Loaders::BatchModelLoader.new(::Ai::Catalog::ItemVersion, version_id).find)
        end

        def with_item(lazy_version)
          Gitlab::Graphql::Lazy.with_value(lazy_version) do |version|
            version&.tap { |v| v.item = object }
          end
        end

        def load_item_consumer_configuration(container_item_pairs:, loader:, container_type:)
          consumers = ::Ai::Catalog::ItemConsumer.for_container_item_pairs(container_type, container_item_pairs)
          consumers.find_each do |consumer|
            container_id = container_type == :project ? consumer.project_id : consumer.group_id
            loader.call([container_id, consumer.ai_catalog_item_id], consumer)
          end
        end

        def self.resolve_type(item, _context)
          RESOLVE_TYPES[item.item_type.to_sym] or raise "Unknown catalog item type: #{item.item_type}" # rubocop:disable Style/AndOr -- Syntax error when || is used
        end
      end
    end
  end
end
