# frozen_string_literal: true

module Types
  module Authz
    class LdapAdminRoleSyncStatusEnum < BaseEnum
      graphql_name 'LdapAdminRoleSyncStatus'
      description 'All LDAP admin role sync statuses.'

      ::Authz::LdapAdminRoleLink.sync_statuses.each_key do |status|
        value status.upcase,
          description: "A sync that is #{status.tr('_', ' ')}.",
          value: status
      end
    end
  end
end
