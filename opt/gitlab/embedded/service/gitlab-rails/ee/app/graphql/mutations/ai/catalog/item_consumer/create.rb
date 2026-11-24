# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module ItemConsumer
        class Create < BaseMutation
          graphql_name 'AiCatalogItemConsumerCreate'

          description <<~MD
            Enables a catalog item in a project or top-level group.
            Rate limited to 30 requests per minute per user.
          MD

          include TriggerConditionsConverter
          include ::Mutations::Ai::Catalog::RateLimitable

          RATE_LIMIT_KEY = :ai_catalog_item_consumer_create

          field :item_consumer,
            ::Types::Ai::Catalog::ItemConsumerType,
            null: true,
            description: 'Item configuration created.'

          field :warnings,
            [GraphQL::Types::String],
            null: false,
            description: 'Non-fatal problems encountered while configuring the item. ' \
              'The configuration was still created.'

          argument :item_id, ::Types::GlobalIDType[::Ai::Catalog::Item], # rubocop:disable Graphql/ForbiddenLoadsArgument -- pre-existing code; removing `loads:` would be a breaking change
            required: true,
            loads: ::Types::Ai::Catalog::ItemInterface,
            description: 'Item to configure.'

          argument :target, Types::Ai::Catalog::ItemConsumerTargetInputType,
            required: true,
            description: 'Target project or top-level group in which the catalog item is configured.'

          argument :trigger_types, [GraphQL::Types::String],
            required: false,
            description: 'List of event types to create AI Catalog triggers for ' \
              '(values can be mention, assign or assign_reviewer).'

          argument :trigger_filter, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- filter schema is not model backed
            required: false,
            deprecated: { reason: 'Use `triggerConditions`', milestone: '19.3' },
            description: 'Filter conditions for the auto-created AI Catalog triggers, keyed by event type.'

          argument :trigger_conditions, ::Types::Ai::Catalog::TriggerConditionsInputType,
            required: false,
            experiment: { milestone: '19.3' },
            description: 'Filter conditions for the auto-created AI Catalog triggers, keyed by event type.'

          argument :trigger_goals, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- keyed by event type, not model backed
            required: false,
            experiment: { milestone: '19.5' },
            description: 'Goals for the auto-created AI Catalog triggers, keyed by event type.'

          argument :parent_item_consumer_id, ::Types::GlobalIDType[::Ai::Catalog::ItemConsumer],
            required: false,
            description: 'Parent item consumer belonging to the top-level group.'

          argument :consumer_kind, ::Types::Ai::Catalog::ItemConsumerKindEnum,
            required: false,
            as: :kind,
            default_value: 'direct',
            description: 'Type of item configuration. `INHERITANCE` is only valid for a top-level group target.'

          argument :replace_existing_direct_configurations, GraphQL::Types::Boolean,
            required: false,
            description: 'Confirm replacement of a group configuration, and any project configurations, ' \
              'for this item when inheritance is turned on. Required when the item is already configured for the group.'

          argument :pinned_version, ::Types::Ai::Catalog::PinnedVersionType,
            required: false,
            description: 'Version to pin the item to, in the format `n.n.n`. ' \
              'Must be a released version. Defaults to the latest released version. ' \
              "Ignored when enabling within the item's managing project, " \
              'which always tracks the latest released version.'

          validates mutually_exclusive: [:trigger_filter, :trigger_conditions]

          authorize :create_ai_catalog_item_consumer

          def resolve(item:, target:, trigger_conditions: nil, **args)
            if item.foundational_chat_agent?
              return {
                item_consumer: nil,
                errors: ["Foundational agents must be configured in admin settings."],
                warnings: []
              }
            end

            args[:trigger_filter] = convert_trigger_conditions_to_h(trigger_conditions) if trigger_conditions.present?

            group_id = target[:group_id]
            group = group_id ? authorized_find!(id: group_id) : nil
            project_id = target[:project_id]
            project = project_id ? authorized_find!(id: project_id) : nil
            parent_item_consumer_id = args[:parent_item_consumer_id]
            parent_item_consumer = parent_item_consumer_id ? find_parent_item_consumer(parent_item_consumer_id) : nil

            raise_resource_not_available_error! unless allowed?(item)

            return rate_limited_response if rate_limited?(RATE_LIMIT_KEY, scope: { user: current_user })

            result = ::Ai::Catalog::ItemConsumers::CreateService.new(
              container: group || project,
              current_user: current_user,
              params: service_args(item, parent_item_consumer, args)
            ).execute

            {
              item_consumer: result.payload[:item_consumer],
              errors: result.errors,
              warnings: Array(result.payload[:warnings])
            }
          end

          private

          def rate_limited_response
            {
              item_consumer: nil,
              errors: [s_('AICatalog|You have enabled items too many times. Try again in a minute.')],
              warnings: []
            }
          end

          def allowed?(item)
            Ability.allowed?(current_user, :read_ai_catalog_item, item)
          end

          def find_parent_item_consumer(parent_item_consumer_id)
            parent = GitlabSchema.object_from_id(
              parent_item_consumer_id, expected_type: ::Ai::Catalog::ItemConsumer
            ).sync

            unless parent && Ability.allowed?(current_user, :read_ai_catalog_item_consumer, parent.group)
              raise_resource_not_available_error!
            end

            parent
          end

          def service_args(item, parent_item_consumer, args)
            args[:item] = item
            args[:parent_item_consumer] = parent_item_consumer
            args
          end
        end
      end
    end
  end
end
