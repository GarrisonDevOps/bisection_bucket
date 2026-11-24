# frozen_string_literal: true

class AddAdminRolesFkToLdapAdminRoleLinks < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    add_concurrent_foreign_key :ldap_admin_role_links, :admin_roles, column: :admin_role_id, on_delete: :cascade # rubocop:disable Migration/ForeignKeysToDestroyServiceTables, Lint/RedundantCopDisableDirective -- backstop until Authz::AdminRole guards LDAP links, see destroy_service_foreign_keys_todo.yml
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :ldap_admin_role_links, column: :admin_role_id
    end
  end
end
