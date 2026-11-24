# frozen_string_literal: true

module Mutations
  module MemberRoles
    module Admin
      class Update < Base
        graphql_name 'MemberRoleAdminUpdate'

        authorize :update_admin_role
        authorize_granular_token permissions: :update_admin_member_role, boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        argument :id, ::Types::GlobalIDType[::MemberRole],
          required: true,
          description: 'ID of the member role to mutate.'

        def ready?(**args)
          if args.except(:id).blank?
            raise Gitlab::Graphql::Errors::ArgumentError, 'The list of member_role attributes is empty'
          end

          super
        end

        def resolve(**args)
          member_role = authorized_find!(id: args.delete(:id))

          unless member_role.admin_related_role?
            raise Gitlab::Graphql::Errors::ArgumentError, 'This mutation can only be used to update admin member roles'
          end

          params = canonicalize_for_update(args,
            available_permissions: ::Gitlab::CustomRoles::Definition.admin.keys)

          response = ::MemberRoles::UpdateService.new(current_user, params).execute(member_role)

          {
            member_role: response.payload,
            errors: response.errors
          }
        end
      end
    end
  end
end
