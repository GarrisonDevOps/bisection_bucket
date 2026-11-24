# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    # Syncs that run once per project after its policies were linked with defer_policy_mr_sync
    module ProjectWideSyncs
      private

      def schedule_project_wide_syncs(linked_policies)
        approval_policies = linked_policies.select(&:type_approval_policy?)
        return if approval_policies.empty?

        schedule_finding_enrichments_sync(approval_policies)
        schedule_merge_requests_sync
      end

      # This is a project wide sync, so one job per project is enough
      def schedule_finding_enrichments_sync(approval_policies)
        policy = Security::Policy.id_in(approval_policies.map(&:id)).with_enrichment_filters.first
        return unless policy

        Security::ScanResultPolicies::SyncProjectFindingEnrichmentsWorker.perform_async(project.id, policy.id)
      end

      def schedule_merge_requests_sync
        return unless project.merge_requests.opened.any?

        Security::ScanResultPolicies::SyncMergeRequestsForProjectWorker.perform_async(project.id, configuration.id)
      end
    end
  end
end
