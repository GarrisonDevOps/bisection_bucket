# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncMergeRequestsForProjectWorker
      include ApplicationWorker

      data_consistency :sticky
      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once

      concurrency_limit -> { 300 }
      defer_on_database_health_signal :gitlab_main, [:approval_merge_request_rules, :scan_result_policy_violations],
        1.minute

      feature_category :security_policy_management

      def perform(project_id, configuration_id)
        project = Project.find_by_id(project_id)

        return unless project
        return unless project.security_policies.for_policy_configuration_ids(configuration_id).exists?

        Security::SecurityOrchestrationPolicies::SyncMergeRequestsService.new(
          project: project,
          policy_configuration_id: configuration_id
        ).execute
      end
    end
  end
end
