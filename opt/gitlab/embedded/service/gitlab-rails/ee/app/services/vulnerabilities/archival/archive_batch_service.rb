# frozen_string_literal: true

module Vulnerabilities
  module Archival
    class ArchiveBatchService
      def self.execute(...)
        new(...).execute
      end

      def initialize(vulnerability_archive, batch)
        @vulnerability_archive = vulnerability_archive
        @batch = batch
      end

      def execute
        archive_vulnerabilities
        update_vulnerability_statistics
      end

      private

      attr_reader :vulnerability_archive, :batch

      delegate :project, to: :vulnerability_archive, private: true

      def archive_vulnerabilities
        Vulnerability.feature_flagged_transaction_for(project) do
          create_archived_records
          update_archived_records_count
          delete_records
        end
      end

      def create_archived_records
        Vulnerabilities::ArchivedRecord.bulk_insert!(archived_records)
      end

      def update_archived_records_count
        vulnerability_archive.increment!(:archived_records_count, vulnerabilities.length)
      end

      def delete_records
        Vulnerabilities::Removal::RemoveFromProjectService::BatchRemoval.new(
          project,
          vulnerabilities,
          update_counts: true,
          backup: vulnerability_archive.date
        ).execute
      end

      def archived_records
        vulnerabilities.map { |vulnerability| build_archived_record_for(vulnerability) }
      end

      def build_archived_record_for(vulnerability)
        Vulnerabilities::Archival::ArchivedRecordBuilderService.execute(vulnerability_archive, vulnerability)
      end

      def update_vulnerability_statistics
        Vulnerabilities::Statistics::AdjustmentWorker.perform_async([project.id])
      end

      # Locking records here will probably cause deadlock issue but not locking them
      # will most likely introduce a deadlock issue.
      # We need to stop ingestion process while running the archival logic.
      def vulnerabilities
        @vulnerabilities ||= Vulnerability.id_in(batch).with_archival_related_entities.lock!
      end
    end
  end
end
