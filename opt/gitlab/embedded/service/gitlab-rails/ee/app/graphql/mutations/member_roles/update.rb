# frozen_string_literal: true

module Mutations
  module MemberRoles
    class Update < Base
      graphql_name 'MemberRoleUpdate'

      authorize :admin_member_role
      authorize_granular_token permissions: :update_member_role,
        boundaries: [
          { boundary_argument: :id, boundary: :namespace, boundary_type: :group, assignable_when: [:saas] },
          { boundary: :instance, boundary_type: :instance, assignable_when: [:admin] }
        ]

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

        params = canonicalize_for_update(args)
        response = ::MemberRoles::UpdateService.new(current_user, params).execute(member_role)

        {
          member_role: response.payload,
          errors: response.errors
        }
      end
    end
  end
end
