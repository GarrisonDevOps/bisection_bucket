# frozen_string_literal: true

module API
  module Entities
    class LdapGroupLink < Grape::Entity
      expose :cn, documentation: { type: 'String', example: 'ldap-group-1' }
      expose :group_access, documentation: { type: 'Integer', example: 10 }
      expose :provider, documentation: { type: 'String', example: 'ldapmain' }
      expose :filter, documentation: { type: 'String', example: 'id >= 500' }, if: ->(_, _) do
        ::License.feature_available?(:ldap_group_sync_filter)
      end
      expose :member_role_id,
        documentation: { type: 'Integer', format: 'int64', example: 12 }, if: ->(ldap_group_link, _) do
          ldap_group_link.group.custom_roles_enabled?
        end
    end
  end
end
