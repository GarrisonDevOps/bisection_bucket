# frozen_string_literal: true

module Mutations
  module WorkItems
    module Types
      class AvailabilityToggle < BaseMutation
        graphql_name 'WorkItemAvailabilityToggle'
        description 'Enables or disables a work item type for a namespace.'

        include Mutations::ResolvesNamespace

        authorize :update_work_item_type_visibility
        authorize_granular_token permissions: :update_work_item_type_visibility,
          boundaries: [
            { boundary_argument: :full_path, boundary_type: :project },
            { boundary_argument: :full_path, boundary_type: :group }
          ]

        argument :full_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the group or project.'

        argument :work_item_type_id, ::Types::GlobalIDType[::WorkItems::Type],
          required: true,
          prepare: ->(gid, _ctx) { gid.model_id },
          description: 'Global ID of the work item type.'

        argument :action, ::Types::WorkItems::AvailabilityActionEnum,
          required: true,
          description: 'Whether to enable or disable the work item type.'

        argument :scope, ::Types::WorkItems::AvailabilityScopeEnum,
          required: true,
          description: 'Whether to apply to the namespace or propagate to all existing children.'

        field :work_item_type, ::Types::WorkItems::TypeType,
          null: true,
          description: 'Work item type after the availability change.'

        def resolve(full_path:, work_item_type_id:, action:, scope:)
          namespace = authorized_find!(full_path: full_path)
          raise_resource_not_available_error! unless customizable_type_visibility_enabled?(namespace)

          type_provider = provider(namespace)
          type = type_provider.find_by_id(work_item_type_id)
          raise_resource_not_available_error! unless type && Ability.allowed?(current_user, :read_work_item_type, type)

          result = ::WorkItems::TypesFramework::VisibilityUpdateService.new(
            namespace: namespace,
            work_item_type_id: work_item_type_id,
            enabled: action == :enable,
            propagate: scope == :all_children
          ).execute

          if result.success?
            type_provider.invalidate_cache!
            { work_item_type: type_provider.find_by_id(work_item_type_id), errors: [] }
          else
            { work_item_type: nil, errors: result.errors }
          end
        end

        private

        def find_object(full_path:)
          resolve_namespace(full_path: full_path)
        end

        def provider(namespace)
          ::WorkItems::TypesFramework::Provider.new(namespace)
        end

        def customizable_type_visibility_enabled?(namespace)
          ::WorkItems::Settings.for_namespace(namespace)&.customizable_type_visibility
        end
      end
    end
  end
end
