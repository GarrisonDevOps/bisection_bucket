# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class CreatePipelineWorker # rubocop:disable Scalability/IdempotentWorker -- The worker should not run multiple times to avoid creating multiple pipelines
      include ApplicationWorker
      include Security::ScanExecutionPolicies::PipelineCreation

      feature_category :security_policy_management
      deduplicate :until_executing
      urgency :throttled
      data_consistency :delayed
      worker_resource_boundary :cpu

      concurrency_limit -> { 1000 }

      def perform(project_id, current_user_id, schedule_id, branch)
        project = Project.find_by_id(project_id)
        return unless project

        # When per-project scheduling is enabled, RunScheduleWorker handles execution.
        # This guard prevents orphaned perform_in jobs (from the old RuleScheduleService
        # path) from creating duplicate pipelines after the feature flag is enabled.
        return if Feature.enabled?(:scan_execution_policy_per_project_scheduling, project)

        current_user = User.find_by_id(current_user_id)
        return unless current_user

        schedule = Security::OrchestrationPolicyRuleSchedule.find_by_id(schedule_id)
        return unless schedule

        create_scan_execution_pipeline(project: project, user: current_user, rule_schedule: schedule, branch: branch)
      end
    end
  end
end
