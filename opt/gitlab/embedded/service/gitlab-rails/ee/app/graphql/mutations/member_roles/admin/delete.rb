# frozen_string_literal: true

module Mutations
  # rubocop:disable Gitlab/BoundedContexts -- the MemberRole module already exists and holds the other mutations as well
  module MemberRoles
    module Admin
      class Delete < ::Mutations::BaseMutation
        graphql_name 'MemberRoleAdminDelete'

        authorize :delete_admin_role
        authorize_granular_token permissions: :delete_admin_member_role, boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        argument :id, ::Types::GlobalIDType[::MemberRole],
          required: true,
          description: 'ID of the admin member role to delete.'

        field :member_role, ::Types::MemberRoles::MemberRoleType, description: 'Deleted admin member role.'

        def resolve(**args)
          member_role = authorized_find!(id: args.delete(:id))

          unless member_role.admin_related_role?
            raise Gitlab::Graphql::Errors::ArgumentError, 'This mutation is restricted to deleting admin roles only'
          end

          response = ::MemberRoles::DeleteService.new(current_user).execute(member_role)

          {
            member_role: response.payload,
            errors: response.errors
          }
        end
      end
    end
  end
  # rubocop:enable Gitlab/BoundedContexts
end
