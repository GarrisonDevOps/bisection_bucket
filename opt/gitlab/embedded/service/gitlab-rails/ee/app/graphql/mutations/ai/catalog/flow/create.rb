# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module Flow
        class Create < BaseMutation
          graphql_name 'AiCatalogFlowCreate'

          include Gitlab::Graphql::Authorize::AuthorizeResource
          include ::Mutations::Ai::Catalog::ConfigValidationRateLimitable

          field :item,
            ::Types::Ai::Catalog::FlowType,
            null: true,
            description: 'Item created.'

          argument :description, GraphQL::Types::String,
            required: true,
            description: 'Description for the flow.'

          argument :name, GraphQL::Types::String,
            required: true,
            description: 'Name for the flow.'

          argument :project_id, ::Types::GlobalIDType[::Project],
            required: true,
            description: 'Project for the flow.'

          argument :public, GraphQL::Types::Boolean,
            required: false,
            deprecated: { reason: 'Use `visibility`', milestone: '19.2' },
            description: 'Whether the flow is publicly visible in the catalog.'

          argument :visibility, ::Types::Ai::Catalog::ItemVisibilityEnum,
            required: false,
            experiment: { milestone: '19.2' },
            description: 'Visibility of the flow in the catalog.'

          argument :release, GraphQL::Types::Boolean,
            required: false,
            description: 'Whether to release the latest version of the flow.'

          argument :definition, GraphQL::Types::String,
            required: false,
            description: 'YAML definition for the flow.'

          authorize :create_ai_catalog_flow
          authorize_granular_token permissions: :create_ai_catalog_flow,
            boundary_argument: :project_id, boundary_type: :project

          validates exactly_one_of: [:public, :visibility]

          def resolve(args)
            project = authorized_find!(id: args[:project_id])

            return { item: nil, errors: [config_validation_rate_limited_message] } if config_validation_rate_limited?

            service_args = args.except(:project_id)

            result = ::Ai::Catalog::Flows::CreateService.new(
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
