# frozen_string_literal: true

module Security
  class SyncMergeRequestsWorker # rubocop:disable Scalability/IdempotentWorker -- Not guaranteed to be idempotent
    include ApplicationWorker

    data_consistency :sticky
    urgency :low
    deduplicate :until_executing
    defer_on_database_health_signal :gitlab_main
    concurrency_limit -> { 200 }

    feature_category :security_policy_management

    def perform(project_id, policy_id)
      project = Project.find_by_id(project_id)
      return unless project

      policy = Security::Policy.find_by_id(policy_id)
      return unless policy

      Security::SecurityOrchestrationPolicies::SyncMergeRequestsService
        .new(project: project, security_policy: policy)
        .execute
    end
  end
end
