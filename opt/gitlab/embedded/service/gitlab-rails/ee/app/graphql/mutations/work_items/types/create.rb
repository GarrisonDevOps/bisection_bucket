# frozen_string_literal: true

module Mutations
  module WorkItems
    module Types
      class Create < BaseMutation
        graphql_name 'WorkItemTypeCreate'

        include Mutations::ResolvesGroup
        include Gitlab::Utils::StrongMemoize
        include Mutations::WorkItems::RequiresFullPathForGranularTokens

        authorize :create_work_item_type
        authorize_granular_token permissions: :create_work_item_type, boundary_argument: :full_path,
          boundary_type: :group

        field :work_item_type, ::Types::WorkItems::TypeType,
          null: true,
          description: 'Work item type that was created.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name for the work item type.'

        argument :icon_name, GraphQL::Types::String,
          required: true,
          description: "Icon name for the work item type. Use the `workItemTypeIconDefinitions` query to " \
            "retrieve the list of available icon names."

        argument :full_path, GraphQL::Types::String,
          required: false,
          description: 'Full path of the root group.'

        argument :enabled_by_default_for_new_namespaces, GraphQL::Types::Boolean,
          required: false,
          description: 'Indicates the type is enabled by default for new child namespaces.'

        def resolve(full_path: nil, **args)
          namespace = authorized_find!(full_path: full_path)

          response = ::WorkItems::Types::CreateService.new(
            container: namespace,
            current_user: current_user,
            params: args
          ).execute

          if response.success?
            resource_parent = response.payload[:resource_parent]
            context[:resource_parent] = resource_parent
            response_object = ::WorkItems::TypesFramework::Provider.new(resource_parent)
              .fetch_work_item_type(response.payload[:work_item_type])
          end

          response_errors = response.error? ? Array(response.errors) : []

          {
            work_item_type: response_object,
            errors: response_errors
          }
        end

        private

        def find_object(full_path: nil)
          if full_path.present?
            resolve_group(full_path: full_path)
          else
            context[:current_organization]
          end
        end
      end
    end
  end
end
