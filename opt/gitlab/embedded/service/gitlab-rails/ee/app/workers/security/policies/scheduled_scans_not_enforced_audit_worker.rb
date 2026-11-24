# frozen_string_literal: true

module Security
  module Policies
    class ScheduledScansNotEnforcedAuditWorker
      include ApplicationWorker

      data_consistency :sticky

      feature_category :security_policy_management
      urgency :low
      idempotent!
      deduplicate :until_executed
      defer_on_database_health_signal :gitlab_main, [:project_audit_events], 1.minute

      # Audit stream to external destination with HTTP request if configured
      worker_has_external_dependencies!

      def perform(project_id, current_user_id, schedule_id, branch)
        project = Project.find_by_id(project_id) || return
        return unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)

        schedule = Security::OrchestrationPolicyRuleSchedule.find_by_id(schedule_id) || return
        current_user = User.find_by_id(current_user_id) || return

        ::Security::SecurityOrchestrationPolicies::ScheduledScansNotEnforcedAuditor.new(project: project,
          author: current_user,
          schedule: schedule,
          branch: branch).audit
      end
    end
  end
end
