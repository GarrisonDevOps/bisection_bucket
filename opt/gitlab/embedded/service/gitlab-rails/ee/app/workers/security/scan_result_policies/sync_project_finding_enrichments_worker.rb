# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncProjectFindingEnrichmentsWorker
      include ApplicationWorker

      data_consistency :sticky
      idempotent!

      feature_category :security_policy_management
      urgency :low
      defer_on_database_health_signal :gitlab_sec, [:security_finding_enrichments], 1.minute

      def perform(project_id, security_policy_id)
        project = Project.find_by_id(project_id) || return
        security_policy = Security::Policy.find_by_id(security_policy_id) || return

        return unless security_policy.type_approval_policy?
        return unless security_policy.has_enrichment_filters?

        Security::SyncFindingEnrichmentsService.new(project).execute
      end
    end
  end
end
