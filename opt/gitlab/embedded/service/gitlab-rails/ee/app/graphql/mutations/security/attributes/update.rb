# frozen_string_literal: true

module Mutations
  module Security
    module Attributes
      class Update < BaseMutation
        graphql_name 'SecurityAttributeUpdate'

        authorize :admin_security_attributes
        authorize_granular_token permissions: :update_security_attribute,
          boundary_argument: :id, boundary: :namespace, boundary_type: :group

        argument :color, Types::ColorType,
          required: false,
          description: 'Color of the security attribute.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Description of the security attribute.'

        argument :id, ::Types::GlobalIDType[::Security::Attribute],
          required: true,
          description: 'Global ID of the security attribute.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Name of the security attribute.'

        field :security_attribute, Types::Security::AttributeType,
          null: true,
          description: 'Updated security attribute.'

        def resolve(id:, **params)
          attribute = authorized_find!(id: id)

          result = ::Security::Attributes::UpdateService.new(
            attribute: attribute,
            current_user: current_user,
            params: params
          ).execute

          {
            security_attribute: result.success? ? result.payload[:attribute] : nil,
            errors: result.errors
          }
        end
      end
    end
  end
end
