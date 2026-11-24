# frozen_string_literal: true

module Mutations
  module Authz
    module LdapAdminRoleLinks
      class Create < BaseMutation
        graphql_name 'LdapAdminRoleLinkCreate'
        description "Creates an instance-level custom admin role LDAP link"

        authorize_granular_token permissions: :create_ldap_admin_role_link, boundary: :instance,
          boundary_type: :instance,
          assignable_when: [:admin]

        # TODO: change to type `AdminRole` - https://gitlab.com/gitlab-org/gitlab/-/issues/518003
        argument :admin_member_role_id,
          ::Types::GlobalIDType[::MemberRole],
          required: true,
          description: 'Global ID of the custom admin role to be assigned to a user.'

        argument :provider,
          GraphQL::Types::String,
          required: true,
          description: 'LDAP provider for the LDAP link.'

        argument :cn,
          GraphQL::Types::String,
          required: false,
          description: 'Common Name (CN) of the LDAP group.'

        argument :filter,
          GraphQL::Types::String,
          required: false,
          description: 'Search filter for the LDAP group.'

        field :ldap_admin_role_link,
          Types::Authz::LdapAdminRoleLinkType,
          description: 'Created instance-level LDAP link.'

        validates exactly_one_of: [:cn, :filter]

        def ready?(**args)
          raise_resource_not_available_error! unless Ability.allowed?(current_user, :create_ldap_admin_role_link)

          super
        end

        def resolve(admin_member_role_id:, **args)
          admin_member_role = find_admin_member_role(admin_member_role_id)

          params = args.merge(member_role: admin_member_role, organization_id: Current.organization.id)

          result = ::Authz::LdapAdminRoleLinks::CreateService.new(current_user, params).execute

          return { errors: Array(result.errors) } if result.error?

          {
            ldap_admin_role_link: result.payload[:ldap_admin_role_link],
            errors: []
          }
        end

        private

        def find_admin_member_role(admin_member_role_id)
          admin_member_role = ::Gitlab::Graphql::Lazy.force(find_object(id: admin_member_role_id))

          raise_resource_not_available_error! unless admin_member_role

          admin_member_role
        end
      end
    end
  end
end
