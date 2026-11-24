# frozen_string_literal: true

class AddIndexOnAdminRoleIdToLdapAdminRoleLinks < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  INDEX_NAME = 'index_ldap_admin_role_links_on_admin_role_id'

  def up
    add_concurrent_index :ldap_admin_role_links, :admin_role_id, name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :ldap_admin_role_links, INDEX_NAME
  end
end
