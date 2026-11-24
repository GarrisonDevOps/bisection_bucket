# frozen_string_literal: true

module Vulnerabilities
  module Archival
    class ArchiveService
      BATCH_SIZE = 50

      def self.execute(...)
        new(...).execute
      end

      def initialize(project, archive_before_date)
        @project = project
        @archive_before_date = archive_before_date
        @date = Time.zone.today
        @buffer = []
      end

      def execute
        # This call is here to always create the archive record in the database
        # regardless there are archivable vulnerabilities or not.
        # Otherwise, the list of archives would have no entries for some months
        # which can be surprising for the end user.
        vulnerability_archive

        project.vulnerabilities.each_batch(of: BATCH_SIZE) do |batch|
          process_batch(batch)
        end

        archive(force: true)
      end

      private

      attr_reader :project, :archive_before_date, :date
      attr_accessor :buffer

      def process_batch(batch)
        self.buffer += archivable_vulnerabilities(batch)

        archive
      end

      def archive(force: false)
        return if !force && buffer.length < BATCH_SIZE

        vulnerabilities = buffer.shift(BATCH_SIZE)

        return unless vulnerabilities.present?

        Vulnerabilities::Archival::ArchiveBatchService.execute(vulnerability_archive, vulnerabilities)
      end

      # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- This method doesn't run in a transaction so it doesn't create a save point.
      def vulnerability_archive
        @vulnerability_archive ||= project.vulnerability_archives.safe_find_or_create_by(date: date.beginning_of_month)
      end
      # rubocop:enable Performance/ActiveRecordSubtransactionMethods

      def archivable_vulnerabilities(batch)
        batch.with_mrs_and_issues.with_triaging_users.select do |vulnerability|
          vulnerability.archive?(archive_before_date)
        end
      end
    end
  end
end
