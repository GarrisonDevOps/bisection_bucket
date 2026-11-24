# frozen_string_literal: true

module Mutations
  module Issuables
    module CustomFields
      class Update < BaseMutation
        graphql_name 'CustomFieldUpdate'

        authorize :admin_custom_field
        authorize_granular_token permissions: :update_custom_field, boundary_argument: :id,
          boundary: :namespace, boundary_type: :group

        field :custom_field, Types::Issuables::CustomFieldType,
          null: true,
          description: 'Updated custom field.'

        argument :id, ::Types::GlobalIDType[::Issuables::CustomField],
          required: true,
          description: copy_field_description(Types::Issuables::CustomFieldType, :id)

        argument :name, GraphQL::Types::String,
          required: false,
          description: copy_field_description(Types::Issuables::CustomFieldType, :name)

        argument :select_options, [Types::Issuables::CustomFieldSelectOptionInputType],
          required: false,
          description: copy_field_description(Types::Issuables::CustomFieldType, :select_options)

        argument :work_item_type_ids, [::Types::GlobalIDType[::WorkItems::Type]],
          required: false,
          description: 'Work item type global IDs associated to the custom field.',
          prepare: ->(global_ids, _ctx) { global_ids.map(&:model_id) }

        def resolve(id:, **args)
          custom_field = authorized_find!(id: id)

          response = ::Issuables::CustomFields::UpdateService.new(
            custom_field: custom_field,
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
      end
    end
  end
end
