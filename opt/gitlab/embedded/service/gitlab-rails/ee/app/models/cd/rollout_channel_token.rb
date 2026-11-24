# frozen_string_literal: true

module Cd
  # Persists the token an AutoFlow channel is opened with (e.g. when a
  # rollout's approval step suspends), so Rails has a handle to push a
  # value into that channel later. See Cd::Rollouts::CallbackToken for the
  # unrelated, stateless workflow -> Rails callback token.
  class RolloutChannelToken < ApplicationRecord
    self.table_name = 'cd_rollout_channel_tokens'

    encrypts :token
    prevent_from_serialization :token

    belongs_to :rollout, class_name: 'Cd::Rollout', inverse_of: :rollout_channel_tokens, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    # The step this channel was opened for (see
    # Cd::Rollouts::WorkflowEvents::ChannelTokens#execute). Nullable: a channel
    # token arriving before that collaborator could resolve a step, or for a
    # gate opened for a non-step reason, has no step to point at.
    belongs_to :rollout_step, class_name: 'Cd::RolloutStep', optional: true

    populate_sharding_key :organization_id, source: :rollout

    # Mirrors Relay's own is_channel_name/is_channel_token limits, not the generic
    # 510-byte guideline, so Rails never rejects a value Relay would accept.
    validates :channel_name, presence: true, bytesize: { maximum: -> { 255 } },
      uniqueness: { scope: :rollout_id }
    validates :token, presence: true, bytesize: { maximum: -> { 4096 } }

    validate :ensure_token_is_string

    class << self
      # Overwrites the token on a re-post of the same channel_name: AutoFlow can
      # redeliver the same post_value on a pre-2xx retry, and the unique index on
      # [rollout_id, channel_name] means a plain create would otherwise conflict.
      def upsert_token!(rollout:, channel_name:, token:, rollout_step: nil)
        rollout.rollout_channel_tokens.find_or_initialize_by(channel_name: channel_name).tap do |channel_token|
          channel_token.token = token
          channel_token.rollout_step = rollout_step
          channel_token.save!
        end
      end
    end

    private

    # bytesize/presence coerce non-String values via #to_s before checking, so
    # they wouldn't catch e.g. a Hash token.
    def ensure_token_is_string
      errors.add(:token, 'must be a string') unless token.is_a?(String) || token.nil?
    end
  end
end
