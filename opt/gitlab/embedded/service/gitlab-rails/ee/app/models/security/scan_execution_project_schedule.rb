# frozen_string_literal: true

module Security
  class ScanExecutionProjectSchedule < ApplicationRecord
    include Security::CronSchedulableWithDelay

    self.table_name = 'security_scan_execution_project_schedules'

    belongs_to :policy_rule_schedule, class_name: 'Security::OrchestrationPolicyRuleSchedule',
      inverse_of: :project_schedules
    belongs_to :project
    belongs_to :security_policy, class_name: 'Security::Policy', inverse_of: :scan_execution_project_schedules

    validates :policy_rule_schedule, :project, :security_policy, :next_run_at, presence: true
    validates :policy_rule_schedule_id, uniqueness: { scope: :project_id }

    scope :for_project, ->(project) { where(project: project) }
    scope :for_security_policy, ->(security_policy) { where(security_policy: security_policy) }
    scope :for_rule_schedules, ->(rule_schedules) { where(policy_rule_schedule: rule_schedules) }
    scope :runnable_schedules, -> { where(next_run_at: ...Time.zone.now) }
    scope :ordered_by_next_run_at, -> { order(:next_run_at, :id) }
    scope :including_rule_schedule_and_project, -> {
      includes(project: :namespace, policy_rule_schedule: :security_orchestration_policy_configuration)
    }

    def self.create_if_not_exists(
      policy_rule_schedule:, project:, security_policy:, next_run_at:,
      next_run_applied_delay:)
      now = Time.zone.now

      result = insert_all(
        [{
          policy_rule_schedule_id: policy_rule_schedule.id,
          project_id: project.id,
          security_policy_id: security_policy.id,
          next_run_at: next_run_at,
          next_run_applied_delay: next_run_applied_delay,
          created_at: now,
          updated_at: now
        }],
        unique_by: %i[policy_rule_schedule_id project_id]
      )

      result.rows.any?
    end

    delegate :time_window, :time_window_seconds, :cron, :cron_timezone, to: :policy_rule_schedule, allow_nil: true
  end
end
