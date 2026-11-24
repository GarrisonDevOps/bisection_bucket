# frozen_string_literal: true

module Cd
  class Rollout < ApplicationRecord
    include AfterCommitQueue

    self.table_name = 'cd_rollouts'

    TERMINAL_STATES = %i[completed failed cancelled].freeze

    belongs_to :version_set, class_name: 'Cd::VersionSet', inverse_of: :rollouts, optional: false
    belongs_to :application, class_name: 'Cd::Application', inverse_of: :rollouts, optional: false
    belongs_to :application_flow_definition, class_name: 'Cd::ApplicationFlowDefinition', optional: true
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    has_many :rollout_environments, -> { ordered },
      class_name: 'Cd::RolloutEnvironment', inverse_of: :rollout
    has_many :rollout_transitions, -> { ordered },
      class_name: 'Cd::RolloutTransition', inverse_of: :rollout
    has_many :rollout_steps, -> { ordered },
      class_name: 'Cd::RolloutStep', inverse_of: :rollout
    # The AutoFlow capabilities for this rollout's workflow, created by
    # Cd::Rollouts::StartService (see Cd::RolloutWorkflowToken).
    has_one :workflow_token, class_name: 'Cd::RolloutWorkflowToken', inverse_of: :rollout
    has_many :rollout_channel_tokens, class_name: 'Cd::RolloutChannelToken', inverse_of: :rollout
    has_many :incoming_events, class_name: 'Cd::RolloutIncomingEvent', inverse_of: :rollout

    populate_sharding_key :organization_id, source: :version_set

    # In before_create (not before_validation) so the application row lock is held across the INSERT.
    before_create :ensure_iid

    scope :in_organization, ->(organization) { where(organization_id: organization) }

    scope :search_by_iid, ->(term) {
      normalized = term.to_s.delete_prefix('#').strip
      normalized.match?(/\A\d+\z/) ? where(iid: Integer(normalized, 10)) : none
    }

    # workflow_ref is set when the rollout is kicked off (see
    # Cd::Rollouts::StartService), which also transitions it out of the initial
    # pending state, so it is required in every non-pending state.
    #
    # `cancelled` is an exception: it is reachable directly from `pending` (see
    # the `cancel` event below), so a rollout that was cancelled before ever
    # starting is exempt too. `started_at` (only ever set on entry to
    # `in_progress`) is what distinguishes this case from a rollout that
    # started and was cancelled later, which must still carry a workflow_ref.
    validates :workflow_ref, length: { maximum: 255 }
    validates :workflow_ref, presence: true, unless: -> { pending? || (cancelled? && started_at.nil?) }

    # State machine defining the rollout lifecycle.
    # See https://gitlab.com/groups/gitlab-org/-/work_items/21247#rollout-states
    state_machine :state, initial: :pending do
      # -- Forward flow --
      event :start do
        transition pending: :in_progress
      end

      event :pause do
        transition in_progress: :paused
      end

      event :resume do
        transition paused: :in_progress
      end

      event :complete do
        transition in_progress: :completed
      end

      # Named `fail_rollout` to avoid conflict with Ruby's `Kernel#fail`.
      event :fail_rollout do
        transition in_progress: :failed
      end

      # -- Cancellation --
      # `failed` is intentionally excluded: it is a terminal state, so it has
      # no outgoing transitions.
      # See https://gitlab.com/gitlab-org/gitlab/-/work_items/601918#note_3424864477
      event :cancel do
        transition [:pending, :in_progress, :paused] => :cancelled
      end

      # -- Callbacks --
      before_transition any => :in_progress do |rollout|
        rollout.started_at ||= Time.current
      end

      before_transition any => TERMINAL_STATES do |rollout|
        rollout.finished_at = Time.current
      end

      # `reason: nil` since starting is a plain status update, not a Duo-engagement
      # event (see Types::Cd::RolloutUpdateReasonEnum).
      after_transition pending: :in_progress do |rollout|
        rollout.run_after_commit do
          GraphqlTriggers.cd_rollout_updated(rollout, nil)
          rollout.notify_release_status_change
        end
      end

      after_transition any => TERMINAL_STATES do |rollout|
        rollout.run_after_commit { rollout.notify_release_status_change }
      end
    end

    enum :state, {
      pending: 0,
      in_progress: 1,
      paused: 2,
      completed: 3,
      failed: 4,
      cancelled: 5
    }

    # Maps the high-level statuses exposed via the GraphQL API to the
    # underlying state machine states they group together.
    STATES_BY_STATUS = {
      'active' => %w[pending in_progress paused],
      'succeeded' => %w[completed],
      'failed' => %w[failed cancelled]
    }.freeze

    scope :for_statuses, ->(statuses) { where(state: states_for(statuses)) }

    # Unknown statuses are silently ignored (contribute no states) rather than
    # raising or matching a null state, since STATES_BY_STATUS#values_at would
    # otherwise return nil for them.
    def self.states_for(statuses)
      statuses.flat_map { |status| STATES_BY_STATUS.fetch(status, []) }
    end

    def sync_state_from_steps!
      return unless in_progress?

      fail_rollout if rollout_steps.where(state: RolloutStep::FAILURE_STATES).exists?
    end

    def notify_release_status_change
      affected_release_version_sets.each { |version_set| GraphqlTriggers.cd_version_set_updated(version_set) }
    end

    # A completed rollout also supersedes each environment's previous version set,
    # so their statuses change alongside the target's.
    def affected_release_version_sets
      sets = [version_set]
      sets.concat(rollout_environments.preload(:previous_version_set).filter_map(&:previous_version_set)) if completed?

      sets.uniq
    end

    # Whether this rollout has an open approval gate: an unresolved
    # request_approval in its transition journal. Approval is a gate, not a
    # state, so this is derived rather than read off `state`.
    # See Cd::RolloutTransition::GATE_EVENTS.
    def open_approval_gate?
      open_gate_transition.present?
    end

    # The request_approval transition currently open on this rollout, if any.
    # Kept separate from open_approval_gate? for callers (e.g.
    # Cd::Rollouts::ResolveGateService) that need the transition itself --
    # for example to read its rollout_step -- rather than just a boolean;
    # open_approval_gate? delegates here so both share the one query.
    #
    # Ties on created_at are broken by id, matching
    # Cd::RolloutTransition.open_gate_rollout_ids. `reorder` (not `order`) is
    # required here: the rollout_transitions association applies its own
    # `ordered` (created_at ASC) scope, which `order` would only append to,
    # leaving that ascending clause dominant over this method's own ordering.
    def open_gate_transition
      transition = rollout_transitions.gate_events.reorder(created_at: :desc, id: :desc).first

      transition if transition&.event == Cd::RolloutTransition::EVENT_REQUEST_APPROVAL
    end

    # The channel token opened for the given rollout_step, if any. Callers
    # resolving a gate pass the gate's own request_approval transition's
    # rollout_step (see Cd::Rollouts::ResolveGateService) to get back the
    # exact channel that step opened -- populated by
    # Cd::Rollouts::WorkflowEvents::ChannelTokens#execute from the same event
    # that opened the gate. `rollout_step: nil` matches tokens with no step
    # reference, which is correct rather than a fallback: a gate opened for a
    # non-step reason has no step to match against either.
    def current_gate_channel_token(rollout_step)
      rollout_channel_tokens.find_by(rollout_step: rollout_step)
    end

    private

    def ensure_iid
      self.iid = application.next_rollout_iid! if iid.blank?
    end
  end
end
