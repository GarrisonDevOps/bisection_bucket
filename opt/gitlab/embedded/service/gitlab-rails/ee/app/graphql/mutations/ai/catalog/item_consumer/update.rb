# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module ItemConsumer
        class Update < BaseMutation
          graphql_name 'AiCatalogItemConsumerUpdate'

          field :item_consumer,
            ::Types::Ai::Catalog::ItemConsumerType,
            null: true,
            description: 'Item consumer that was updated.'

          argument :id, ::Types::GlobalIDType[::Ai::Catalog::ItemConsumer],
            required: true,
            description: 'Global ID of the catalog item consumer to update.'

          argument :pinned_version_prefix, ::Types::Ai::Catalog::PinnedVersionType,
            required: false,
            deprecated: { reason: 'Use `pinnedVersion` instead', milestone: '19.0' },
            description: 'Version the item is pinned to, in the format `n.n.n`.'

          argument :pinned_version, ::Types::Ai::Catalog::PinnedVersionType,
            required: false,
            description: 'Version the item is pinned to, in the format `n.n.n`.'

          argument :service_account_id, ::Types::GlobalIDType[::User],
            required: false,
            description: 'Service account to associate with the item consumer.'

          argument :trigger_types, [GraphQL::Types::String],
            required: false,
            description: 'List of event types to create flow triggers for ' \
              '(values can be mention, assign or assign_reviewer).'

          authorize :admin_ai_catalog_item_consumer
          authorize_granular_token permissions: :update_ai_catalog_item_consumer,
            boundaries: [
              { boundary_argument: :id, boundary: :project, boundary_type: :project },
              { boundary_argument: :id, boundary: :group, boundary_type: :group }
            ]

          validates exactly_one_of: [:pinned_version, :pinned_version_prefix]

          def resolve(args)
            item_consumer = authorized_find!(id: args[:id])

            pinned = args[:pinned_version] || args[:pinned_version_prefix]
            params = { pinned_version_prefix: pinned }

            result = ::Ai::Catalog::ItemConsumers::UpdateService.new(
              item_consumer,
              current_user,
              params
            ).execute

            item_consumer = result.payload[:item_consumer]
            item_consumer.reset unless result.success?

            {
              item_consumer: item_consumer,
              errors: result.errors
            }
          end
        end
      end
    end
  end
end
