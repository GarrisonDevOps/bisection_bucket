# frozen_string_literal: true

module Mutations
  module WorkItems
    module Lifecycles
      class Delete < BaseMutation
        graphql_name 'LifecycleDelete'

        include Mutations::ResolvesGroup

        authorize :admin_work_item_lifecycle
        authorize_granular_token permissions: :delete_work_item_lifecycle, boundary_argument: :namespace_path,
          boundary_type: :group

        field :lifecycle, ::Types::WorkItems::LifecycleType,
          null: true,
          description: 'Deleted lifecycle.'

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Namespace path where the lifecycle exists.'

        argument :id, ::Types::GlobalIDType[::WorkItems::Statuses::Lifecycle],
          required: true,
          description: 'Global ID of the lifecycle to delete.'

        def resolve(namespace_path:, **args)
          group = authorized_find!(namespace_path: namespace_path)

          response = ::WorkItems::Lifecycles::DeleteService.new(
            container: group,
            current_user: current_user,
            params: args
          ).execute

          response_object = response.payload[:lifecycle] if response.success?
          response_errors = response.error? ? Array(response.errors) : []

          {
            lifecycle: response_object,
            errors: response_errors
          }
        end

        private

        def find_object(namespace_path:)
          resolve_group(full_path: namespace_path)
        end
      end
    end
  end
end
