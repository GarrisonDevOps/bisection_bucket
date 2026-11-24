# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module ItemVersion
        class Restore < BaseMutation
          graphql_name 'AiCatalogItemVersionRestore'

          include ::Mutations::Ai::Catalog::ConfigValidationRateLimitable

          field :item_version,
            ::Types::Ai::Catalog::VersionInterface,
            null: true,
            description: 'Newly created item version restored from the source version.'

          argument :id, ::Types::GlobalIDType[::Ai::Catalog::ItemVersion],
            required: true,
            description: 'Global ID of the item version to restore from.'

          argument :deprecate_current, GraphQL::Types::Boolean,
            required: false,
            default_value: false,
            description: 'Whether to mark the current latest version as deprecated.'

          authorize :restore_ai_catalog_item
          authorize_granular_token permissions: :restore_ai_catalog_item,
            boundary_argument: :id, boundary: :project, boundary_type: :project

          def resolve(id:, deprecate_current:)
            source_version = authorized_find!(id: id)

            if config_validation_rate_limited?
              return { item_version: nil, errors: [config_validation_rate_limited_message] }
            end

            result = ::Ai::Catalog::ItemVersions::RestoreService.new(
              project: source_version.project,
              current_user: current_user,
              params: { source_version: source_version, deprecate_current: deprecate_current }
            ).execute

            {
              item_version: result.payload[:item_version],
              errors: result.errors
            }
          end
        end
      end
    end
  end
end
