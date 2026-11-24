# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module ItemConsumer
        class Delete < BaseMutation
          graphql_name 'AiCatalogItemConsumerDelete'

          description <<~MD
            Disables a catalog item in a project or top-level group.
            Rate limited to 30 requests per minute per user.
          MD

          include ::Mutations::Ai::Catalog::RateLimitable

          RATE_LIMIT_KEY = :ai_catalog_item_consumer_delete

          field :success, GraphQL::Types::Boolean,
            null: false,
            description: 'Returns true if catalog item consumer was successfully deleted.'

          argument :id, ::Types::GlobalIDType[::Ai::Catalog::ItemConsumer],
            required: true,
            description: 'Global ID of the catalog item consumer to delete.'

          authorize :admin_ai_catalog_item_consumer
          authorize_granular_token permissions: :delete_ai_catalog_item_consumer,
            boundaries: [
              { boundary_argument: :id, boundary: :project, boundary_type: :project },
              { boundary_argument: :id, boundary: :group, boundary_type: :group }
            ]

          def resolve(id:)
            item_consumer = authorized_find!(id: id)

            return rate_limited_response if rate_limited?(RATE_LIMIT_KEY, scope: { user: current_user })

            result = ::Ai::Catalog::ItemConsumers::DestroyService.new(item_consumer, current_user).execute

            {
              success: result.success?,
              errors: Array(result.errors)
            }
          end

          private

          def rate_limited_response
            {
              success: false,
              errors: [s_('AICatalog|You have disabled items too many times. Try again in a minute.')]
            }
          end
        end
      end
    end
  end
end
