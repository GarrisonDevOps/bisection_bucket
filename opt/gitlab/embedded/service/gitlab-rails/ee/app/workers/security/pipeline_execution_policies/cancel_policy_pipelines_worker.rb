# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class CancelPolicyPipelinesWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_policy_management
      urgency :low
      defer_on_database_health_signal :gitlab_main, [:security_policies]

      def perform(security_policy_id, project_id)
        security_policy = Security::Policy.find_by_id(security_policy_id)
        project = Project.find_by_id(project_id)
        return unless security_policy && project

        CancelPolicyPipelinesService.new(
          security_policy: security_policy,
          project: project
        ).execute
      end
    end
  end
end
