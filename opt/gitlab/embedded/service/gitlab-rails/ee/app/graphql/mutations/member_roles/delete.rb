# frozen_string_literal: true

module Mutations
  module MemberRoles
    class Delete < ::Mutations::BaseMutation
      graphql_name 'MemberRoleDelete'

      authorize :admin_member_role
      authorize_granular_token permissions: :delete_member_role,
        boundaries: [
          { boundary_argument: :id, boundary: :namespace, boundary_type: :group, assignable_when: [:saas] },
          { boundary: :instance, boundary_type: :instance, assignable_when: [:admin] }
        ]

      argument :id, ::Types::GlobalIDType[::MemberRole],
        required: true,
        description: 'ID of the member role to delete.'

      field :member_role, ::Types::MemberRoles::MemberRoleType,
        description: 'Deleted member role.', null: true

      def resolve(id:)
        member_role = authorized_find!(id: id)

        if member_role.admin_related_role?
          raise Gitlab::Graphql::Errors::ArgumentError, 'This mutation can only be used to delete standard member roles'
        end

        response = ::MemberRoles::DeleteService
          .new(current_user)
          .execute(member_role)

        {
          member_role: response.payload,
          errors: response.errors
        }
      end
    end
  end
end
