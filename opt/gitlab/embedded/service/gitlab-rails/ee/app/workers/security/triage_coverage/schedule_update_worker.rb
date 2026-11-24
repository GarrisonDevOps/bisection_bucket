# frozen_string_literal: true

module Security
  module TriageCoverage
    class ScheduleUpdateWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      urgency :low
      defer_on_database_health_signal :gitlab_sec, [:security_inventory_filters]
      concurrency_limit -> { 50 }

      BATCH_SIZE = 100
      DELAY = 15.seconds.to_i

      # Projects to recompute can be an explicit list of ids, or every project attached to a profile
      def perform(project_ids = nil, scan_profile_id = nil)
        if scan_profile_id
          schedule_for_scan_profile(scan_profile_id)
        else
          schedule_for_project_ids(project_ids)
        end
      end

      private

      def schedule_for_scan_profile(scan_profile_id)
        Security::ScanProfileProject.for_scan_profiles(scan_profile_id).each_batch(of: BATCH_SIZE) do |batch, index|
          UpdateWorker.perform_in(DELAY * (index - 1), batch.project_ids)
        end
      end

      def schedule_for_project_ids(project_ids)
        return unless project_ids.present?

        project_ids.each_slice(BATCH_SIZE).each_with_index do |projects_slice, index|
          UpdateWorker.perform_in(DELAY * index, projects_slice)
        end
      end
    end
  end
end
