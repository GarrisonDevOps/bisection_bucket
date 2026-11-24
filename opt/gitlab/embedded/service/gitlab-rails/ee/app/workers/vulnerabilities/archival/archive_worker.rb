# frozen_string_literal: true

module Vulnerabilities
  module Archival
    class ArchiveWorker
      include ApplicationWorker

      data_consistency :sticky
      idempotent!
      deduplicate :until_executing, including_scheduled: true

      feature_category :vulnerability_management

      def perform(project_id, archive_before)
        project = Project.find_by_id(project_id)

        return unless project

        archive_before_date = Date.parse(archive_before)

        Vulnerabilities::Archival::ArchiveService.execute(project, archive_before_date)
      rescue Date::Error => e
        Gitlab::ErrorTracking.track_exception(e)
      end
    end
  end
end
