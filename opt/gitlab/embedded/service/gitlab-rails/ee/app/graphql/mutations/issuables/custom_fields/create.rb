# frozen_string_literal: true

module Mutations
  module Issuables
    module CustomFields
      class Create < BaseMutation
        graphql_name 'CustomFieldCreate'

        include Mutations::ResolvesGroup

        authorize :admin_custom_field
        authorize_granular_token permissions: :create_custom_field, boundary_argument: :group_path,
          boundary_type: :group

        field :custom_field, Types::Issuables::CustomFieldType,
          null: true,
          description: 'Created custom field.'

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group path where the custom field is created.'

        argument :field_type, ::Types::Issuables::CustomFieldTypeEnum,
          required: true,
          description: copy_field_description(Types::Issuables::CustomFieldType, :field_type)

        argument :name, GraphQL::Types::String,
          required: true,
          description: copy_field_description(Types::Issuables::CustomFieldType, :name)

        argument :select_options, [Types::Issuables::CustomFieldSelectOptionInputType],
          required: false,
          description: copy_field_description(Types::Issuables::CustomFieldType, :select_options)

        argument :work_item_type_ids, [::Types::GlobalIDType[::WorkItems::Type]],
          required: false,
          description: 'Work item type global IDs associated to the custom field.',
          prepare: ->(global_ids, _ctx) { global_ids.map(&:model_id) }

        def resolve(group_path:, **args)
          group = authorized_find!(group_path: group_path)

          response = ::Issuables::CustomFields::CreateService.new(
            group: group,
            current_user: current_user,
            params: args
          ).execute

          response_object = response.payload[:custom_field] if response.success?
          response_errors = response.error? ? Array(response.errors) : []

          {
            custom_field: response_object,
            errors: response_errors
          }
        end

        private

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end
      end
    end
  end
end
