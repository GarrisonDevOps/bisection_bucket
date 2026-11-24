# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module ScanExecutionPolicies
      class CreateProjectSchedulesService
        include Gitlab::Utils::StrongMemoize
        include Gitlab::Loggable

        EVENT_KEY = 'scheduled_scan_execution_policy_schedule_persistence_failure'

        def initialize(project:, security_policy:)
          @project = project
          @security_policy = security_policy
        end

        def execute
          return if Feature.disabled?(:scan_execution_policy_project_schedule_creation, project)
          return if rule_schedules.empty?

          ApplicationRecord.transaction do
            delete_existing_project_schedules(rule_schedules)
            create_project_schedules(rule_schedules)
          end
        rescue StandardError => e
          log_project_schedules_creation_error(e, security_policy)

          raise e
        end

        private

        attr_reader :project, :security_policy

        def rule_schedules
          Security::OrchestrationPolicyRuleSchedule
            .for_scan_execution_policy(security_policy)
            .with_configuration
        end
        strong_memoize_attr :rule_schedules

        def delete_existing_project_schedules(rule_schedules)
          Security::ScanExecutionProjectSchedule
            .for_rule_schedules(rule_schedules)
            .for_project(project)
            .delete_all
        end

        def create_project_schedules(rule_schedules)
          now = Time.zone.now
          rows = rule_schedules.filter_map do |rule_schedule|
            next if rule_schedule.next_run_at.nil?

            capped_time_window = rule_schedule.effective_time_window(nil, defer_cap: true)
            delay = capped_time_window.to_i > 0 ? Random.rand(capped_time_window) : 0

            {
              policy_rule_schedule_id: rule_schedule.id,
              project_id: project.id,
              security_policy_id: security_policy.id,
              next_run_at: rule_schedule.next_run_at + delay.seconds,
              next_run_applied_delay: delay,
              created_at: now,
              updated_at: now
            }
          end

          return if rows.empty?

          Security::ScanExecutionProjectSchedule.insert_all(
            rows,
            unique_by: %i[policy_rule_schedule_id project_id]
          )
        end

        def log_project_schedules_creation_error(error, policy)
          Gitlab::AppJsonLogger.error(
            build_structured_payload(
              event: EVENT_KEY,
              exception_class: error.class.name,
              exception_message: error.message,
              project_id: project.id,
              policy_id: policy.id))
        end
      end
    end
  end
end
