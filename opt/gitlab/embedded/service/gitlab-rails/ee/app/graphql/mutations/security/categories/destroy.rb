# frozen_string_literal: true

module Mutations
  module Security
    module Categories
      class Destroy < BaseMutation
        graphql_name 'SecurityCategoryDestroy'

        authorize :admin_security_attributes
        authorize_granular_token permissions: :delete_security_category,
          boundary_argument: :id, boundary: :namespace, boundary_type: :group

        argument :id, ::Types::GlobalIDType[::Security::Category],
          required: true,
          description: 'Global ID of the security category to destroy.'

        # rubocop:disable GraphQL/ExtractType -- Simple destroy mutation with two related fields
        field :deleted_category_gid, ::Types::GlobalIDType[::Security::Category],
          null: true,
          description: 'Global ID of the deleted security category.'

        field :deleted_attributes_gid, [::Types::GlobalIDType[::Security::Attribute]],
          null: true,
          description: 'Global IDs of the deleted security attributes.'
        # rubocop:enable GraphQL/ExtractType

        def resolve(id:)
          category = authorized_find!(id: id)

          response = ::Security::Categories::DestroyService.new(
            category: category,
            current_user: current_user
          ).execute

          return error_response(response.errors) if response.error?

          success_response(response.payload[:deleted_category_gid], response.payload[:deleted_attributes_gid])
        end

        private

        def error_response(errors)
          { errors: errors }
        end

        def success_response(deleted_category_gid, deleted_attributes_gid)
          {
            deleted_category_gid: deleted_category_gid,
            deleted_attributes_gid: deleted_attributes_gid,
            errors: []
          }
        end
      end
    end
  end
end
