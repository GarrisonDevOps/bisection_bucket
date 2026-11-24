# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module ItemConsumer
        class BulkCreate < BaseMutation
          graphql_name 'AiCatalogItemConsumerBulkCreate'

          description <<~MD
            Enables a catalog item in multiple projects in the background.
            Rate limited to 10 requests per minute per user.
          MD

          include TriggerConditionsConverter
          include ::Mutations::Ai::Catalog::RateLimitable

          argument :item_id, ::Types::GlobalIDType[::Ai::Catalog::Item],
            required: true,
            description: 'Global ID of the catalog item to enable.'

          MAX_PROJECTS = 100
          RATE_LIMIT_KEY = :ai_catalog_item_consumer_bulk_create

          argument :project_ids, [::Types::GlobalIDType[::Project]],
            required: true,
            validates: { length: { maximum: MAX_PROJECTS } },
            description: "Global IDs of the projects to enable the catalog item in (maximum #{MAX_PROJECTS})."

          argument :trigger_types, [GraphQL::Types::String],
            required: false,
            description: 'List of event types to create AI Catalog triggers for.'

          argument :trigger_filter, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- filter schema is not model backed, disabled for the same reason in Mutations::Ai::Catalog::ItemConsumer::Create
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

          argument :pinned_version, ::Types::Ai::Catalog::PinnedVersionType,
            required: false,
            description: 'Version to pin the item to, in the format `n.n.n`. ' \
              'Must be a released version. Defaults to the latest released version. ' \
              "Ignored when enabling within the item's managing project, " \
              'which always tracks the latest released version.'

          validates mutually_exclusive: [:trigger_filter, :trigger_conditions]

          authorize :read_ai_catalog_item
          # No `authorize_granular_token` directive: this mutation writes item consumers to every
          # project in `project_ids`, which `EnqueueBulkCreateService` only constrains to the item's
          # organization -- not to the item's project or namespace. A boundary derived from `item_id`
          # would therefore authorize writes outside the token's boundary, and the boundary extractor
          # cannot resolve an array of Global IDs into a boundary. Tracked in the GraphQL
          # authorization todo file alongside `AiCatalogItemConsumerCreate`.

          def resolve(
            item_id:, project_ids:, trigger_types: nil, trigger_filter: nil, trigger_conditions: nil,
            trigger_goals: nil, pinned_version: nil)
            trigger_filter = convert_trigger_conditions_to_h(trigger_conditions) if trigger_conditions.present?

            item = authorized_find!(id: item_id)

            return rate_limited_response if rate_limited?(RATE_LIMIT_KEY, scope: { user: current_user })

            result = ::Ai::Catalog::ItemConsumers::EnqueueBulkCreateService
              .new(current_user:, item:, project_ids:, trigger_types:, trigger_filter:, trigger_goals:,
                pinned_version:).execute

            { errors: result.errors }
          end

          private

          def rate_limited_response
            { errors: [s_('AICatalog|You have enabled items in bulk too many times. Try again in a minute.')] }
          end
        end
      end
    end
  end
end
