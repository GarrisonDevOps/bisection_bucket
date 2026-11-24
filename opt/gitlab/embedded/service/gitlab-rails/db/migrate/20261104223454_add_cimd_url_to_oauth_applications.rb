# frozen_string_literal: true

class AddCimdUrlToOauthApplications < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    with_lock_retries do
      add_column :oauth_applications, :cimd_url, :text, if_not_exists: true
    end

    add_text_limit :oauth_applications, :cimd_url, 2048
  end

  def down
    with_lock_retries do
      remove_column :oauth_applications, :cimd_url, if_exists: true
    end
  end
end
