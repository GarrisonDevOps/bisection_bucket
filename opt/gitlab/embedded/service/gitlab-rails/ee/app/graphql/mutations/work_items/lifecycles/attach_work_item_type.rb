# frozen_string_literal: true

module Mutations
  module WorkItems
    module Lifecycles
      class AttachWorkItemType < BaseMutation
        graphql_name 'LifecycleAttachWorkItemType'

        include Mutations::ResolvesGroup

        authorize :admin_work_item_lifecycle
        authorize_granular_token permissions: :update_work_item_lifecycle, boundary_argument: :namespace_path,
          boundary_type: :group

        field :lifecycle, ::Types::WorkItems::LifecycleType,
          null: true,
          description: 'Lifecycle after attaching the work item type.'

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Namespace path where the lifecycle exists.'

        argument :work_item_type_id, ::Types::GlobalIDType[::WorkItems::Type],
          required: true,
          description: 'Global ID of the work item type to attach to the lifecycle.'

        argument :lifecycle_id, ::Types::GlobalIDType[::WorkItems::Statuses::Lifecycle],
          required: true,
          description: 'Global ID of the lifecycle to attach the work item type to.'

        argument :status_mappings, [::Types::WorkItems::StatusMappingInputType],
          required: false,
          description: 'Status mappings from the old lifecycle to the new lifecycle.'

        def resolve(namespace_path:, **args)
          group = authorized_find!(namespace_path: namespace_path)

          response = ::WorkItems::Lifecycles::AttachWorkItemTypeService.new(
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
