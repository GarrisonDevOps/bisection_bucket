# frozen_string_literal: true

module Ai
  class FlowSchedule < ApplicationRecord
    extend ::Gitlab::Utils::Override
    include CronSchedulable
    include Limitable

    self.table_name = :ai_flow_schedules
    self.limit_name = 'ai_flow_schedules'
    self.limit_scope = :project

    MAX_CONSECUTIVE_FAILURES = 3

    belongs_to :project, optional: false
    belongs_to :flow_trigger, class_name: 'Ai::FlowTrigger',
      foreign_key: :ai_flow_trigger_id, inverse_of: :flow_schedules, optional: false

    validates :cron, cron: true, presence: true, length: { maximum: 255 }
    validates :cron_timezone, cron_timezone: true, presence: true, length: { maximum: 255 }
    validates :description, presence: true, length: { maximum: 255 }

    validate :flow_trigger_project_matches, if: :flow_trigger
    validate :flow_trigger_runs_on_a_schedule, on: :create, if: :flow_trigger

    before_save :reset_consecutive_failure_count, if: -> { active_changed?(from: false, to: true) }

    enum :last_run_status, { success: 0, sa_invalid: 1, execution_error: 2 }, prefix: :last_run

    scope :active, -> { where(active: true) }
    scope :preload_project_route, -> { preload(project: :route) }
    scope :failed_for_flow_triggers, ->(flow_triggers) do
      where(flow_trigger: flow_triggers).where.not(last_run_status: [nil, :success])
    end

    delegate :service_account, to: :flow_trigger

    def worker_cron_expression
      Gitlab::SidekiqConfig.cron_jobs['ai_flow_schedule_worker']['cron']
    end

    # Guards Schedulable's `before_save :set_next_run_at` so that run-state saves
    # (record_success!/record_failure!) don't recalculate next_run_at and silently
    # push the next run forward. Only cron, timezone, or reactivation changes may.
    override :allow_next_run_at_update?
    def allow_next_run_at_update?
      cron_changed? || cron_timezone_changed? || active_changed?(from: false, to: true)
    end

    # Explicitly calculate next_run_at before saving, matching
    # Ci::PipelineSchedule#schedule_next_run! -- the before_save callback
    # won't fire when allow_next_run_at_update? is false (no cron/tz/activation change).
    override :schedule_next_run!
    def schedule_next_run!
      set_next_run_at unless allow_next_run_at_update?

      super
    end

    def record_success!
      update!(
        consecutive_failure_count: 0,
        last_run_status: :success,
        last_run_error: nil,
        last_run_at: Time.current
      )
    end

    def record_failure!(error_message, status: :execution_error)
      new_count = consecutive_failure_count + 1
      attrs = {
        consecutive_failure_count: new_count,
        last_run_status: status,
        last_run_error: error_message&.truncate(1024),
        last_run_at: Time.current
      }
      deactivate = new_count >= MAX_CONSECUTIVE_FAILURES
      attrs[:active] = false if deactivate

      transaction do
        update!(attrs)
        # Bypasses FlowTriggers::UpdateService and validations on purpose: a trigger that no longer passes
        # validation (for example supported_events) must still turn off. audit_flow_trigger_deactivation audits it.
        flow_trigger.update_columns(active: false, updated_at: Time.current) if deactivate
      end

      audit_flow_trigger_deactivation if deactivate
    end

    def deactivated_by_failures?
      !active? && consecutive_failure_count >= MAX_CONSECUTIVE_FAILURES
    end

    def deactivate!
      update!(active: false, consecutive_failure_count: 0)
    end

    private

    def audit_flow_trigger_deactivation
      ::Gitlab::Audit::Auditor.audit(
        name: 'flow_trigger_updated',
        author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
        scope: flow_trigger.container,
        target: flow_trigger,
        target_details: "#{flow_trigger.description} (ID: #{flow_trigger.id})",
        message: "Deactivated flow trigger after #{MAX_CONSECUTIVE_FAILURES} consecutive failures of its schedule",
        additional_details: { active: { from: true, to: false } }
      )
    end

    def reset_consecutive_failure_count
      self.consecutive_failure_count = 0
    end

    def flow_trigger_project_matches
      return if flow_trigger.project_id == project_id

      errors.add(:base, 'flow_trigger project does not match project')
    end

    def flow_trigger_runs_on_a_schedule
      return if flow_trigger.scheduled?

      errors.add(:base, 'flow_trigger does not run on a schedule')
    end
  end
end
