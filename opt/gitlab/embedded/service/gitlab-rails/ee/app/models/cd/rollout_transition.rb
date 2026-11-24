# frozen_string_literal: true

module Cd
  class RolloutTransition < ApplicationRecord
    include Cd::Concerns::PrincipalReference

    self.table_name = 'cd_rollout_transitions'

    STATES = {
      initial: 0,
      pending: 1,
      in_progress: 2,
      paused: 3,
      completed: 4,
      failed: 5,
      cancelled: 6
    }.freeze

    # Approval is a gate on a rollout, not a state (see the CD Rails design doc,
    # "Lifecycle, gates, and the transition journal"): an unresolved
    # `request_approval` event is an open gate, closed by a subsequent
    # `approve`/`reject`. These are the only events that ever open or close one.
    #
    # The canonical spellings live here (not in Cd::Rollouts::ResolveGateService,
    # which writes EVENT_APPROVE/EVENT_REJECT) so the read side (this class) and
    # the write side can't drift out of sync on the literal event strings.
    EVENT_REQUEST_APPROVAL = 'request_approval'
    EVENT_APPROVE = 'approve'
    EVENT_REJECT = 'reject'
    GATE_EVENTS = [EVENT_REQUEST_APPROVAL, EVENT_APPROVE, EVENT_REJECT].freeze

    belongs_to :rollout, class_name: 'Cd::Rollout', inverse_of: :rollout_transitions, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    # The step a gate-opening request_approval transition was opened for (see
    # Cd::Rollouts::WorkflowEvents::RolloutTransition#open_gate). Nullable: only
    # gate-opening rows populate it today, and the CD Rails design doc expects
    # gates to eventually open for non-step reasons too (see Cd::RolloutGate).
    belongs_to :rollout_step, class_name: 'Cd::RolloutStep', optional: true

    populate_sharding_key :organization_id, source: :rollout

    scope :ordered, -> { order(created_at: :asc) }
    scope :gate_events, -> { where(event: GATE_EVENTS) }

    validates :event, presence: true, length: { maximum: 72 }
    validates :from_state, presence: true
    validates :to_state, presence: true
    validates :principal, presence: true, length: { maximum: 255 }
    validates :on_behalf_of, length: { maximum: 255 }
    validates :reason, length: { maximum: 2000 }
    validates :resolution_reason, length: { maximum: 2000 }
    validates :triggered_by, length: { maximum: 255 }

    enum :from_state, STATES, prefix: :from
    enum :to_state, STATES, prefix: :to

    def self.first_acting_user_id_by_rollout(rollout_ids)
      first_acting_user_id_by(rollout_ids, :rollout_id)
    end

    # The ids, among the given rollout_ids, of rollouts whose latest gate event
    # is an unresolved request_approval -- that is, rollouts with an open
    # approval gate. DISTINCT ON picks the latest gate event per rollout
    # directly in Postgres, mirroring first_acting_user_id_by above.
    def self.open_gate_rollout_ids(rollout_ids)
      gate_events
        .where(rollout_id: rollout_ids)
        .select('DISTINCT ON (rollout_id) rollout_id, event')
        .order(Arel.sql('rollout_id, created_at DESC, id DESC'))
        .filter_map { |transition| transition.rollout_id if transition.event == EVENT_REQUEST_APPROVAL }
    end

    def readonly?
      persisted?
    end
  end
end
