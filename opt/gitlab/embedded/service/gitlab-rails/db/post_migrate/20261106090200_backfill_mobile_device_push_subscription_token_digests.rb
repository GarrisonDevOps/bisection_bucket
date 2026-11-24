# frozen_string_literal: true

class BackfillMobileDevicePushSubscriptionTokenDigests < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  restrict_gitlab_migration gitlab_schema: :gitlab_main_user

  BATCH_SIZE = 100

  class MobileDevicePushSubscription < MigrationRecord
    include EachBatch

    self.table_name = 'mobile_device_push_subscriptions'

    # Rows written before 19.6 hold deterministic ciphertext under the
    # deterministic key. The previous scheme reads them; writes go through
    # the default, non-deterministic scheme. Mirrors the application model.
    encrypts :device_token, previous: { deterministic: true }

    def self.duplicate_of(subscription, digest)
      where.not(id: subscription.id)
        .find_by(device_token_digest: digest, apns_environment: subscription.apns_environment)
    end
  end

  # Gives every row its lookup digest and re-encrypts its token in place; the
  # table is small (one row per registered device). Duplicates from the mixed
  # old/new rollout window are reduced to the most recently seen row.
  def up
    MobileDevicePushSubscription.where(device_token_digest: nil).each_batch(of: BATCH_SIZE) do |batch|
      batch.each { |subscription| backfill(subscription) }
    end
  end

  def down
    # no-op. Rows re-encrypted here are readable only by code that declares the
    # non-deterministic scheme, so a rollback to 19.5 code needs a re-encryption
    # step first. The schema migration's down drops the digest column.
  end

  private

  def backfill(subscription)
    token = subscription.device_token
    # The jsonb cast turns anything that is not a JSON string into nil. (The
    # database testing pipeline stubs decryption with a placeholder, so every
    # row takes this path there.)
    return skip(subscription, 'token did not decrypt to a string') unless token.is_a?(String)

    token = token.downcase
    digest = Digest::SHA256.hexdigest(token)

    return unless remove_older_duplicate(subscription, digest)

    # update_columns serializes the plaintext through the current scheme
    # exactly once, which is how ActiveRecord::Encryption's own `encrypt`
    # rewrites a row.
    subscription.update_columns(device_token: token, device_token_digest: digest)
  rescue ActiveRecord::RecordNotUnique
    # A registration inserted this digest after the duplicate check. The new
    # row is the one the device is using, so this row goes.
    subscription.delete
  rescue ActiveRecord::Encryption::Errors::Base => e
    skip(subscription, e.class)
  end

  # Keeps the more recently seen row and returns true when that is `subscription`.
  # Registrations run concurrently and find rows by digest, so they can refresh or
  # insert the duplicate but never touch `subscription`: the delete re-checks last_seen_at.
  def remove_older_duplicate(subscription, digest)
    duplicate = MobileDevicePushSubscription.duplicate_of(subscription, digest)
    return true unless duplicate

    deleted = MobileDevicePushSubscription
      .where(id: duplicate.id, last_seen_at: ...subscription.last_seen_at)
      .delete_all
    return true if deleted == 1

    subscription.delete
    false
  end

  # A token that does not decrypt cannot be delivered to either. The row keeps
  # a NULL digest: the device re-registers on its next launch and the prune
  # worker removes the stale row.
  def skip(subscription, reason)
    say "Skipping mobile_device_push_subscriptions row #{subscription.id}: #{reason}"
  end
end
