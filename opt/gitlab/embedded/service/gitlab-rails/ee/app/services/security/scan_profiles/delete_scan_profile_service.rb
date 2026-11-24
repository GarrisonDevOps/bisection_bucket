# frozen_string_literal: true

module Security
  module ScanProfiles
    class DeleteScanProfileService
      include Security::ScanProfiles::SchedulesTriageCoverageUpdate

      BATCH_SIZE = 500

      def self.execute(scan_profile_id)
        new(scan_profile_id: scan_profile_id).execute
      end

      def initialize(scan_profile_id:)
        @scan_profile = Security::ScanProfile.find_by_id(scan_profile_id)
      end

      def execute
        return unless scan_profile.present?

        delete_all_profile_connections
        # The FK cascade would otherwise drop every status row in a single statement;
        # batch them ourselves so a profile linked to many projects does not hold locks
        # on a large unbounded delete.
        delete_all_profile_statuses
        # #destroy is overridden on the model to soft-delete; the mutation soft-deletes
        # synchronously and this async path performs the actual hard delete after the
        # project-association cleanup above.
        scan_profile.really_destroy!
      end

      private

      attr_reader :scan_profile

      def delete_all_profile_connections
        Security::ScanProfileProject
          .for_scan_profiles(scan_profile.id)
          .each_batch(of: BATCH_SIZE) do |batch|
            if scan_profile.remediation?
              project_ids = batch.delete_all_returning(:project_id).flat_map(&:values)
              enqueue_triage_coverage_update(project_ids)
            else
              batch.delete_all
            end
          end
      end

      def delete_all_profile_statuses
        Security::ScanProfileProjectStatus
          .for_scan_profile(scan_profile.id)
          .each_batch(of: BATCH_SIZE) { |batch| batch.delete_all }
      end
    end
  end
end
