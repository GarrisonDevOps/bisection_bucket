# frozen_string_literal: true

module Security
  module ScanProfiles
    class UpdateTraversalIdsWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executing, including_scheduled: true
      data_consistency :sticky

      feature_category :security_testing_configuration
      urgency :low
      concurrency_limit -> { 50 }
      defer_on_database_health_signal :gitlab_sec, [:security_scan_profiles_projects], 1.minute

      def perform(project_ids)
        Security::ScanProfiles::UpdateTraversalIdsService.execute(project_ids)
      end
    end
  end
end
