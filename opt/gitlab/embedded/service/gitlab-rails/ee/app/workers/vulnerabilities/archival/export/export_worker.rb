# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Export
      class ExportWorker
        include ApplicationWorker

        data_consistency :sticky
        idempotent!
        deduplicate :until_executing, including_scheduled: true

        feature_category :vulnerability_management

        sidekiq_retries_exhausted do |job|
          archive_export_id = job['args'].first

          Vulnerabilities::Archival::Export::PurgeWorker.perform_in(24.hours, archive_export_id)
        end

        def perform(archive_export_id)
          archive_export = Vulnerabilities::ArchiveExport.find_by_id(archive_export_id)

          return unless archive_export

          Vulnerabilities::Archival::Export::ExportService.export(archive_export)
        end
      end
    end
  end
end
