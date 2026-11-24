# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module ThirdPartyFlow
        class Create < BaseMutation
          graphql_name 'AiCatalogThirdPartyFlowCreate'

          field :item,
            ::Types::Ai::Catalog::ThirdPartyFlowType,
            null: true,
            description: 'Item created.'

          argument :description, GraphQL::Types::String,
            required: true,
            description: 'Description for the Flow.'

          argument :name, GraphQL::Types::String,
            required: true,
            description: 'Name for the Flow.'

          argument :project_id, ::Types::GlobalIDType[::Project],
            required: true,
            description: 'Project for the Flow.'

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
            required: true,
            description: 'YAML definition for the Flow.'

          authorize :create_ai_catalog_third_party_flow
          authorize_granular_token permissions: :create_ai_catalog_third_party_flow,
            boundary_argument: :project_id, boundary_type: :project

          validates exactly_one_of: [:public, :visibility]

          def resolve(args)
            project = authorized_find!(id: args[:project_id])

            service_args = args.except(:project_id)

            result = ::Ai::Catalog::ThirdPartyFlows::CreateService.new(
              project: project,
              current_user: current_user,
              params: service_args
            ).execute

            { item: result.payload[:item], errors: result.errors }
          end
        end
      end
    end
  end
end
