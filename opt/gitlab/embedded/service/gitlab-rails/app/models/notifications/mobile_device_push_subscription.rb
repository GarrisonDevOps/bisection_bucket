# frozen_string_literal: true

module Notifications
  class MobileDevicePushSubscription < ApplicationRecord
    MAX_SUBSCRIPTIONS_PER_USER = 20
    DEVICE_TOKEN_REGEX = /\A[0-9a-f]{16,200}\z/

    belongs_to :user

    # APNs must receive the raw token at delivery time, so the token is
    # encrypted at rest rather than hashed. The ciphertext is non-deterministic,
    # which keeps the encryption key rotatable; equality lookups and the unique
    # index run on `device_token_digest`, the SHA-256 of the normalized token,
    # which the `device_token=` writer keeps in step with the plaintext.
    #
    # Rows written before 19.6 hold deterministic ciphertext under the
    # deterministic key. The previous scheme keeps them readable until the 19.6
    # post-deployment migration has re-encrypted them. It is removed in 19.7:
    # https://gitlab.com/gitlab-org/gitlab/-/issues/634239
    encrypts :device_token, previous: { deterministic: true }

    # APNs tokens are opaque hex; clients disagree on casing. Uniqueness is
    # enforced on the digest, so normalize to lowercase before hashing to keep
    # one row per device. Normalization also applies to finder values, so
    # lookups match regardless of the caller's casing.
    normalizes :device_token, with: ->(token) { token.downcase }

    enum :platform, { ios: 0, macos: 1 }
    enum :apns_environment, { production: 0, sandbox: 1 }, prefix: :apns
    enum :payload_mode, { full: 0, id_only: 1 }, suffix: :payload

    validates :device_token, presence: true,
      format: { with: DEVICE_TOKEN_REGEX, message: 'must be a hexadecimal APNs device token' }
    validates :bundle_identifier, length: { maximum: 255 }
    validates :device_name, length: { maximum: 255 }
    validates :app_version, length: { maximum: 64 }
    validates :locale, length: { maximum: 32 }
    # The cap applies on create and on reassignment (a device changing hands
    # via `register` is an update that moves the row to a new user). A single
    # registration with a combined condition: declaring the same validation
    # method twice with different `on:` options makes the second registration
    # replace the first (ActiveSupport callback dedup).
    validate :subscriptions_limit, if: -> { new_record? || user_id_changed? }

    # The digest is the lookup key and stays nullable until 19.7, so a NULL
    # would slip past the unique index. Derive it once more on create in
    # case a caller bypassed the `device_token=` writer.
    before_create :ensure_device_token_digest

    scope :with_device_token, ->(device_token) { where(device_token_digest: digest_for(device_token)) }
    scope :excluding_user, ->(user) { where.not(user_id: user.id) }

    # The users other than `user` who registered `device_token`, one entry
    # per row, for the unregister log line. At most one row per APNs
    # environment exists for a token (the unique index), which `limit`
    # makes explicit.
    def self.other_user_ids_for_device_token(device_token, user)
      with_device_token(device_token).excluding_user(user).limit(apns_environments.size).pluck(:user_id)
    end

    # A device registration is identified by (device_token, apns_environment):
    # the same physical device holds different tokens per environment.
    def self.find_or_initialize_for_device(device_token, apns_environment)
      find_or_initialize_by(device_token_digest: digest_for(device_token), apns_environment: apns_environment)
        .tap { |subscription| subscription.device_token = device_token }
    end

    # The lookup key for a plaintext token: a plain SHA-256 of the normalized
    # token. Deliberately not the salted `Gitlab::CryptoHelper.sha256`: its salt
    # derives from `db_key_base`, which would tie every lookup to a key that
    # cannot be rotated, the very coupling this column exists to remove. An APNs
    # token is 32 random bytes, so an unsalted digest gives nothing away.
    def self.digest_for(device_token)
      Digest::SHA256.hexdigest(normalize_value_for(:device_token, device_token).to_s)
    end

    # Subscriptions whose device has not re-registered since the cutoff.
    # last_seen_at is written on every registration and defaults to the row's
    # creation time, so it is never NULL.
    scope :stale, ->(cutoff) { where(last_seen_at: ...cutoff) }

    # The distinct ids among `user_ids` that have at least one registered
    # device. Lets dispatch callers skip enqueues for the (vast) majority of
    # users without one. The result is at most one row per input id, which
    # `limit` makes explicit.
    def self.subscribed_user_ids(user_ids)
      where(user_id: user_ids).distinct.limit(user_ids.size).pluck(:user_id)
    end

    # Keeps the digest in step with the plaintext. `super` applies the
    # normalization first, so the digest always covers the lowercased token.
    def device_token=(value)
      super
      self.device_token_digest = device_token.presence && self.class.digest_for(device_token)
    end

    private

    def ensure_device_token_digest
      self.device_token_digest = self.class.digest_for(device_token)
    end

    def subscriptions_limit
      return unless user
      return if user.mobile_device_push_subscriptions.count < MAX_SUBSCRIPTIONS_PER_USER

      errors.add(:base, "cannot have more than #{MAX_SUBSCRIPTIONS_PER_USER} push subscriptions per user")
    end
  end
end
