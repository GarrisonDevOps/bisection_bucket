# frozen_string_literal: true

module Mutations
  module Authz
    module LdapAdminRoleLinks
      class Destroy < BaseMutation
        graphql_name 'LdapAdminRoleLinkDestroy'
        description "Destroys an instance-level custom admin role LDAP link"

        authorize_granular_token permissions: :delete_ldap_admin_role_link, boundary: :instance,
          boundary_type: :instance,
          assignable_when: [:admin]

        argument :id, Types::GlobalIDType[::Authz::LdapAdminRoleLink],
          required: true,
          description: 'Global ID of the instance-level LDAP link to delete.'

        field :ldap_admin_role_link,
          Types::Authz::LdapAdminRoleLinkType,
          description: 'Deleted instance-level LDAP link.'

        def ready?(id:, **args)
          raise_resource_not_available_error! unless Ability.allowed?(current_user, :delete_ldap_admin_role_link)

          @ldap_admin_role_link = ::Gitlab::Graphql::Lazy.force(find_object(id: id))

          raise_resource_not_available_error! unless @ldap_admin_role_link

          super
        end

        def resolve(**_args)
          params = { id: @ldap_admin_role_link.id }
          result = ::Authz::LdapAdminRoleLinks::DestroyService.new(current_user, params).execute

          return { ldap_admin_role_link: nil, errors: Array(result.errors) } if result.error?

          {
            ldap_admin_role_link: result.payload[:ldap_admin_role_link],
            errors: []
          }
        end
      end
    end
  end
end
