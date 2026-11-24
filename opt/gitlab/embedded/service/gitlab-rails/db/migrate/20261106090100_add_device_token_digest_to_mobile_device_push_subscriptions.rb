# frozen_string_literal: true

class AddDeviceTokenDigestToMobileDevicePushSubscriptions < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :mobile_device_push_subscriptions
  INDEX_NAME = 'idx_mobile_push_subscriptions_on_token_digest_and_environment'

  def up
    add_column TABLE_NAME, :device_token_digest, :text, if_not_exists: true
    add_text_limit TABLE_NAME, :device_token_digest, 64

    # NULLs are distinct, so rows that predate the digest (backfilled by the
    # post-deployment migration of the same milestone) don't collide.
    add_concurrent_index TABLE_NAME, [:device_token_digest, :apns_environment], unique: true, name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
    remove_column TABLE_NAME, :device_token_digest, if_exists: true
  end
end
