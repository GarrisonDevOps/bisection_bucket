# frozen_string_literal: true

class AddIndexTopicsOnOrganizationIdAndLowerSlug < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  INDEX_NAME = 'index_topics_on_organization_id_and_lower_slug'

  def up
    add_concurrent_index :topics, 'organization_id, lower(slug)', where: 'slug IS NOT NULL', name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :topics, INDEX_NAME
  end
end
