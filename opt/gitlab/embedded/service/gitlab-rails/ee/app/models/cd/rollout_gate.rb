# frozen_string_literal: true

module Cd
  # A read-side view of one approval gate on a rollout: a request_approval
  # transition paired with whichever approve/reject transition closed it (or
  # nothing, if it is still open). See Cd::RolloutTransition::GATE_EVENTS and
  # the "Lifecycle, gates, and the transition journal" section of the CD Rails
  # design doc for why a gate is derived from the journal rather than stored
  # as its own row.
  class RolloutGate
    STATES = %i[pending approved rejected].freeze

    attr_reader :request_transition, :resolution_transition

    # Gates for a single rollout, in the order they were opened. Thin wrapper
    # around .for_rollouts for callers that already have one rollout in hand
    # (see .for_rollouts for the pairing algorithm and its assumptions).
    def self.for_rollout(rollout)
      for_rollouts([rollout.id]).fetch(rollout.id, [])
    end

    # Batched form of .for_rollout: builds every gate for every given rollout
    # id in one query (plus one query to preload steps), rather than one
    # query per rollout -- so resolving `gates` across a list of rollouts
    # (for example CdApplication.rollouts) doesn't issue an N+1.
    #
    # Returns a Hash of rollout_id => [Gate, ...], in the order each rollout's
    # gates were opened. A rollout id with no gate events is omitted, not
    # mapped to an empty array.
    #
    # Assumes at most one gate is open at a time per rollout (see the design
    # doc's "Multiple concurrent gates" open question): a resolution is paired
    # with whichever request is currently open for that rollout, not
    # correlated by any other key. If that assumption is ever violated, a
    # resolution pairs with the earliest still-open request rather than a
    # specific one.
    def self.for_rollouts(rollout_ids)
      return {} if rollout_ids.empty?

      # Ordered by (rollout_id, created_at, id) so groups come out already in
      # per-rollout opening order -- group_by below need not re-sort them.
      # `:rollout` is preloaded too: Cd::RolloutGatePolicy#delegate reads
      # #rollout on every gate to authorize it, which would otherwise issue
      # one query per distinct rollout instead of reusing the caller's.
      transitions_by_rollout_id = ::Cd::RolloutTransition
        .gate_events
        .where(rollout_id: rollout_ids)
        .order(:rollout_id, created_at: :asc, id: :asc)
        .includes(:rollout_step, :rollout)
        .group_by(&:rollout_id)

      transitions_by_rollout_id.transform_values { |transitions| pair(transitions) }
    end

    def self.pair(transitions)
      gates = []

      transitions.each do |transition|
        case transition.event
        when ::Cd::RolloutTransition::EVENT_REQUEST_APPROVAL
          gates << new(request_transition: transition)
        when ::Cd::RolloutTransition::EVENT_APPROVE, ::Cd::RolloutTransition::EVENT_REJECT
          open_gate = gates.last
          next if open_gate.nil? || open_gate.resolved?

          open_gate.resolve!(transition)
        end
      end

      gates
    end
    private_class_method :pair

    delegate :rollout, to: :request_transition

    def initialize(request_transition:, resolution_transition: nil)
      @request_transition = request_transition
      @resolution_transition = resolution_transition
    end

    def step
      request_transition.rollout_step
    end

    def resolved?
      resolution_transition.present?
    end

    # Mutates this (otherwise read-only) gate with its resolving transition.
    # Public only so .pair can resolve a sibling instance from `gates.last`;
    # not meant to be called once a gate has left that method.
    def resolve!(resolution_transition)
      @resolution_transition = resolution_transition
    end

    # MVP: a gate's name is its step's name. Once gates can open for non-step
    # reasons (see the design doc's open question), this will need its own
    # derivation rather than delegating to the step.
    def name
      step&.name
    end

    def state
      return :pending unless resolution_transition

      resolution_transition.event == ::Cd::RolloutTransition::EVENT_APPROVE ? :approved : :rejected
    end

    # Why the approval was requested. Distinct from #resolution_reason (why it
    # was approved/rejected), which lives on the resolving transition instead.
    def reason
      request_transition.reason
    end
    alias_method :request_reason, :reason

    def resolution_reason
      resolution_transition&.resolution_reason
    end

    def resolved_at
      resolution_transition&.created_at
    end

    def resolved_by_user_id
      resolution_transition&.principal_user_id
    end
  end
end
