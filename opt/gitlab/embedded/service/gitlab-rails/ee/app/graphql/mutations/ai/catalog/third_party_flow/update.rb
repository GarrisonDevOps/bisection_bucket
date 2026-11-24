# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module ThirdPartyFlow
        class Update < BaseMutation
          graphql_name 'AiCatalogThirdPartyFlowUpdate'

          include ::Mutations::Ai::Catalog::ConfigValidationRateLimitable

          field :item,
            ::Types::Ai::Catalog::ThirdPartyFlowType,
            null: true,
            description: 'Flow that was updated.'

          argument :id, ::Types::GlobalIDType[::Ai::Catalog::Item],
            required: true,
            description: 'Global ID of the catalog Flow to update.'

          argument :description, GraphQL::Types::String,
            required: false,
            description: 'Description for the Flow.'

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Name for the Flow.'

          argument :public, GraphQL::Types::Boolean,
            required: false,
            deprecated: { reason: 'Use `visibility`', milestone: '19.2' },
            description: 'Whether the Flow is publicly visible in the catalog.'

          argument :visibility, ::Types::Ai::Catalog::ItemVisibilityEnum,
            required: false,
            experiment: { milestone: '19.2' },
            description: 'Visibility of the Flow in the catalog.'

          argument :release, GraphQL::Types::Boolean,
            required: false,
            description: 'Whether to release the latest version of the Flow.'

          argument :definition, GraphQL::Types::String,
            required: false,
            description: 'YAML definition for the Flow.'

          argument :version_bump, Types::Ai::Catalog::VersionBumpEnum,
            required: false,
            description: 'Bump version, calculated from the last released version name.'

          authorize :admin_ai_catalog_item
          authorize_granular_token permissions: :update_ai_catalog_third_party_flow,
            boundary_argument: :id, boundary: :project, boundary_type: :project

          validates mutually_exclusive: [:public, :visibility]

          def resolve(args)
            flow = authorized_find!(id: args.delete(:id))

            return { item: nil, errors: [config_validation_rate_limited_message] } if config_validation_rate_limited?

            params = args.merge(item: flow)

            result = ::Ai::Catalog::ThirdPartyFlows::UpdateService.new(
              project: flow.project,
              current_user: current_user,
              params: params
            ).execute

            item = result.payload[:item]
            item.reset

            {
              item: item,
              errors: result.errors
            }
          end
        end
      end
    end
  end
end
