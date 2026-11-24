# frozen_string_literal: true

module Resolvers
  module Authz
    class LdapAdminRoleLinksResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::Authz::LdapAdminRoleLinkType.connection_type, null: true

      def resolve
        raise_resource_not_available_error! unless resource_available?

        ::Authz::LdapAdminRoleLink.all
      end

      private

      def resource_available?
        ::License.feature_available?(:custom_roles) &&
          Ability.allowed?(current_user, :read_ldap_admin_role_link)
      end
    end
  end
end
