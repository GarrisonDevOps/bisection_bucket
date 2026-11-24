# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module Agent
        class Delete < BaseMutation
          graphql_name 'AiCatalogAgentDelete'

          field :success, GraphQL::Types::Boolean,
            null: false,
            description: 'Returns true if catalog Agent was successfully deleted.'

          argument :id, ::Types::GlobalIDType[::Ai::Catalog::Item],
            required: true,
            description: 'Global ID of the catalog Agent to delete.'

          argument :force_hard_delete, GraphQL::Types::Boolean,
            required: false,
            description: 'When true, the flow will always be hard deleted and never soft deleted. ' \
              'Can only be used by instance admins'

          authorize :delete_ai_catalog_item
          authorize_granular_token permissions: :delete_ai_catalog_agent,
            boundary_argument: :id, boundary: :project, boundary_type: :project

          def resolve(args)
            id = args.delete(:id)

            item = authorized_find!(id: id)

            if args[:force_hard_delete] && !Ability.allowed?(current_user, :force_hard_delete_ai_catalog_item)
              raise_resource_not_available_error!('You must be an instance admin to use forceHardDelete')
            end

            service_args = args.merge(item: item)

            result = ::Ai::Catalog::Agents::DestroyService.new(
              project: service_args[:item].project,
              current_user: current_user,
              params: service_args).execute

            {
              success: result.success?,
              errors: Array(result.errors)
            }
          end
        end
      end
    end
  end
end
