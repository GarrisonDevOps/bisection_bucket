# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Export
      class ExportService
        EXPORTERS = {
          'csv' => Vulnerabilities::Archival::Export::Exporters::CsvService
        }.freeze

        def self.export(archive_export)
          new(archive_export).export
        end

        def initialize(archive_export)
          @archive_export = archive_export
        end

        def export
          archive_export.start!

          generate_export_file

          archive_export.store_file_now!
          archive_export.finish!

          schedule_purging_export
        rescue StandardError
          archive_export.reset_state!

          raise
        end

        private

        attr_reader :archive_export

        delegate :project, :format, :date_range, to: :archive_export, private: true

        def generate_export_file
          exporter.generate { |f| archive_export.file = f }
          archive_export.file.filename = filename
        end

        def exporter
          @exporter ||= EXPORTERS[archive_export.format].new(iterator)
        end

        def iterator
          Iterator.new(archive_export.archives)
        end

        def schedule_purging_export
          Vulnerabilities::Archival::Export::PurgeWorker.perform_in(24.hours, archive_export.id)
        end

        def filename
          [
            project.full_path.parameterize,
            '_vulnerabilities_archive_',
            date_range,
            Time.current.utc.strftime('_%FT%H%M'),
            '.',
            format
          ].join
        end

        class Iterator
          include Enumerable

          def initialize(archives)
            @archives = archives
          end

          def each(&block)
            return to_enum(:each) unless block

            archives.each { |archive| yield_archived_records_of(archive, &block) }
          end

          def yield_archived_records_of(archive)
            archive.archived_records.each_batch do |batch|
              batch.each { |archived_record| yield archived_record }
            end
          end

          private

          attr_reader :archives
        end
      end
    end
  end
end
