# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Export
      class PurgeWorker
        include ApplicationWorker

        data_consistency :sticky
        idempotent!
        deduplicate :until_executing, including_scheduled: true

        feature_category :vulnerability_management

        def perform(archive_export_id)
          archive_export = Vulnerabilities::ArchiveExport.find_by_id(archive_export_id)

          return unless archive_export

          Vulnerabilities::Archival::Export::PurgeService.purge(archive_export)
        end
      end
    end
  end
end
