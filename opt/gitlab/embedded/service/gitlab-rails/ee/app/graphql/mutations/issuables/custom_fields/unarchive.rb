# frozen_string_literal: true

module Mutations
  module Issuables
    module CustomFields
      class Unarchive < BaseMutation
        graphql_name 'CustomFieldUnarchive'

        authorize :admin_custom_field
        authorize_granular_token permissions: :unarchive_custom_field, boundary_argument: :id,
          boundary: :namespace, boundary_type: :group

        field :custom_field, Types::Issuables::CustomFieldType,
          null: true,
          description: 'Unarchived custom field.'

        argument :id, ::Types::GlobalIDType[::Issuables::CustomField],
          required: true,
          description: copy_field_description(Types::Issuables::CustomFieldType, :id)

        def resolve(id:)
          custom_field = authorized_find!(id: id)

          response = ::Issuables::CustomFields::UnarchiveService.new(
            custom_field: custom_field,
            current_user: current_user
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
