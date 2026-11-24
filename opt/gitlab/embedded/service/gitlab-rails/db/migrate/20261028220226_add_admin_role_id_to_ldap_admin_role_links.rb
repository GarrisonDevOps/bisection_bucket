# frozen_string_literal: true

class AddAdminRoleIdToLdapAdminRoleLinks < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :ldap_admin_role_links, :admin_role_id, :bigint
  end
end
