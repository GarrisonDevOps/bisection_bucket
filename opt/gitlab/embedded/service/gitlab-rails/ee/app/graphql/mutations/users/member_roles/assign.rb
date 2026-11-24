# frozen_string_literal: true

module Mutations
  module Users
    module MemberRoles
      class Assign < BaseMutation
        graphql_name 'MemberRoleToUserAssign'

        authorize :admin_member_role
        authorize_granular_token permissions: :assign_member_role,
          boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        argument :user_id, Types::GlobalIDType[::User],
          required: true,
          description: 'Global ID of the user to be assigned to a custom role.'

        argument :member_role_id, Types::GlobalIDType[::MemberRole],
          required: false,
          description: 'Global ID of the custom role to be assigned to a user.
            Admin roles will be unassigned from the user if omitted or set as NULL.'

        field :user_member_role, ::Types::Users::UserMemberRoleType,
          description: 'Created user member role or nil if the relation was deleted.', null: true

        def ready?(**args)
          raise_resource_not_available_error! unless Ability.allowed?(current_user, :admin_member_role)

          super
        end

        def resolve(**args)
          user = ::Gitlab::Graphql::Lazy.force(find_object(id: args[:user_id]))

          raise_resource_not_available_error! unless user

          member_role = ::Gitlab::Graphql::Lazy.force(find_object(id: args[:member_role_id]))

          raise_resource_not_available_error! if args[:member_role_id] && !member_role

          params = { user: user, member_role: member_role }

          response = ::Users::MemberRoles::AssignService.new(current_user, params).execute

          raise_resource_not_available_error! if response.error? && response.reason == :unauthorized

          {
            user_member_role: response.payload[:user_member_role],
            errors: response.errors
          }
        end
      end
    end
  end
end
