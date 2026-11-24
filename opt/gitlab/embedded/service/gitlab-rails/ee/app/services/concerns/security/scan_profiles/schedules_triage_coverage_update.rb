# frozen_string_literal: true

module Security
  module ScanProfiles
    module SchedulesTriageCoverageUpdate
      private

      def schedule_triage_coverage_update(project_ids, scan_type:)
        return unless Enums::Security.remediation_scan_profile_types.key?(scan_type.to_sym)

        enqueue_triage_coverage_update(project_ids)
      end

      def schedule_triage_coverage_update_for_profile(profile)
        return unless profile.remediation?

        Security::TriageCoverage::ScheduleUpdateWorker.perform_async(nil, profile.id)
      end

      def enqueue_triage_coverage_update(project_ids)
        return if project_ids.blank?

        Security::TriageCoverage::ScheduleUpdateWorker.perform_async(project_ids)
      end

      def remediation_project_ids(deleted_rows)
        return [] if deleted_rows.empty?

        # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- pluck on Array, not AR relation
        profile_ids = deleted_rows.pluck('security_scan_profile_id').uniq
        # rubocop:enable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit
        remediation_ids = Security::ScanProfile.remediation.id_in(profile_ids).scan_profile_ids.to_set

        deleted_rows
          .filter_map { |row| row['project_id'] if remediation_ids.include?(row['security_scan_profile_id']) }
          .uniq
      end
    end
  end
end
