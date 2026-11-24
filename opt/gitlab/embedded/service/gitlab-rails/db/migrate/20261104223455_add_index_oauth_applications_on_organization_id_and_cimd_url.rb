# frozen_string_literal: true

class AddIndexOauthApplicationsOnOrganizationIdAndCimdUrl < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  INDEX_NAME = 'index_oauth_applications_on_organization_id_and_cimd_url'

  def up
    add_concurrent_index :oauth_applications, [:organization_id, :cimd_url],
      unique: true, where: 'cimd_url IS NOT NULL', name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :oauth_applications, INDEX_NAME
  end
end
