# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class RunScheduleWorker
      include ApplicationWorker
      include Security::ScanExecutionPolicies::PipelineCreation

      idempotent!
      deduplicate :until_executing, including_scheduled: true
      urgency :throttled
      concurrency_limit -> { 1000 }
      data_consistency :sticky
      feature_category :security_policy_management

      def perform(project_schedule_id, options = {})
        raise(ArgumentError, 'options must be of type Hash') unless options.is_a?(Hash) || options.nil?

        project_schedule = Security::ScanExecutionProjectSchedule.find_by_id(project_schedule_id)
        return unless project_schedule

        project = project_schedule.project
        return unless Feature.enabled?(:scan_execution_policy_per_project_scheduling, project)

        return unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)
        return if project.deletion_in_progress_or_scheduled_in_hierarchy_chain?
        return unless project_schedule.security_policy.linked_to_project?(project)

        user = ensure_security_policy_bot_user(project)
        return unless user

        branch = options&.fetch('branch', nil) || project.default_branch_or_main
        rule_schedule = project_schedule.policy_rule_schedule

        create_scan_execution_pipeline(project: project, user: user, rule_schedule: rule_schedule, branch: branch)
      end

      private

      def ensure_security_policy_bot_user(project)
        return project.security_policy_bot if project.security_policy_bot

        Security::Orchestration::CreateBotService
          .new(project, nil, skip_authorization: true)
          .execute

        project.reset.security_policy_bot
      end
    end
  end
end
