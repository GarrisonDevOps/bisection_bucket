# frozen_string_literal: true

module Cd
  # Claims a relay/KAS workflow event callback by (rollout_id, idempotency_key), so a
  # redelivered event (at-least-once delivery) is processed at most once. See
  # Cd::Rollouts::ClaimWorkflowEventService, which owns the insert-wins-or-no-op race,
  # and Cd::Rollouts::ProcessWorkflowEventService, which marks a claim completed in the
  # same transaction as the event's own writes.
  class RolloutIncomingEvent < ApplicationRecord
    include CreatedAtFilterable

    self.table_name = 'cd_rollout_incoming_events'

    belongs_to :rollout, class_name: 'Cd::Rollout', inverse_of: :incoming_events, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    populate_sharding_key :organization_id, source: :rollout

    validates :idempotency_key, presence: true, bytesize: { maximum: -> { 255 } },
      uniqueness: { scope: :rollout_id }

    enum :status, {
      pending: 0,
      completed: 1
    }
  end
end
