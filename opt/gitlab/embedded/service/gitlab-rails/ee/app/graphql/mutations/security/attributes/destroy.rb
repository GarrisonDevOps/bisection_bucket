# frozen_string_literal: true

module Mutations
  module Security
    module Attributes
      class Destroy < BaseMutation
        graphql_name 'SecurityAttributeDestroy'

        authorize :admin_security_attributes
        authorize_granular_token permissions: :delete_security_attribute,
          boundary_argument: :id, boundary: :namespace, boundary_type: :group

        argument :id, ::Types::GlobalIDType[::Security::Attribute],
          required: true,
          description: 'Global ID of the security attribute to destroy.'

        field :deleted_attribute_gid, ::Types::GlobalIDType[::Security::Attribute],
          null: true,
          description: 'Global ID of the destroyed security attribute.'

        def resolve(id:)
          attribute = authorized_find!(id: id)

          result = ::Security::Attributes::DestroyService.new(
            attribute: attribute,
            current_user: current_user
          ).execute

          {
            deleted_attribute_gid: result.success? ? result.payload[:deleted_attribute_gid] : nil,
            errors: result.errors
          }
        end
      end
    end
  end
end
