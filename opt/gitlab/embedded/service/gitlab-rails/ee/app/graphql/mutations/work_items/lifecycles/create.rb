# frozen_string_literal: true

module Mutations
  module WorkItems
    module Lifecycles
      class Create < BaseMutation
        graphql_name 'LifecycleCreate'

        include Mutations::ResolvesGroup

        authorize :admin_work_item_lifecycle
        authorize_granular_token permissions: :create_work_item_lifecycle, boundary_argument: :namespace_path,
          boundary_type: :group

        field :lifecycle, ::Types::WorkItems::LifecycleType,
          null: true,
          description: 'Lifecycle created.'

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Namespace path where the lifecycle will be created.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the lifecycle.'

        argument :statuses, [::Types::WorkItems::StatusInputType],
          required: true,
          description: 'Statuses of the lifecycle. Can be existing (with id) or new (without id).'

        argument :default_open_status_index, GraphQL::Types::Int,
          required: true,
          description: 'Index of the default open status in the statuses array.'

        argument :default_closed_status_index, GraphQL::Types::Int,
          required: true,
          description: 'Index of the default closed status in the statuses array.'

        argument :default_duplicate_status_index, GraphQL::Types::Int,
          required: true,
          description: 'Index of the default duplicated status in the statuses array.'

        def resolve(namespace_path:, **args)
          group = authorized_find!(namespace_path: namespace_path)

          response = ::WorkItems::Lifecycles::CreateService.new(
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
