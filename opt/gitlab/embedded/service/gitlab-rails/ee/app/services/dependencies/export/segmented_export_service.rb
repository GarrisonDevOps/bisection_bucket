# frozen_string_literal: true

module Dependencies # rubocop:disable Gitlab/BoundedContexts -- This is an existing module
  module Export
    # This service class is responsible for;
    #
    # 1) Creating the partial report contents called export parts
    #    via the `export_segment` method.
    # 2) Combining the partial reports together to generate the
    #    final export via the `finalise_segmented_export` method.
    #
    # As seen this service class has multiple responsibilities but the "segmented export"
    # framework expects this interface. We will address this by a refactoring work later.
    class SegmentedExportService
      EXPORTERS = {
        json_array: ::Sbom::Exporters::JsonArrayService,
        csv: ::Sbom::Exporters::CsvService
      }.freeze
      BATCH_SIZE = 1_000

      def initialize(dependency_list_export)
        @dependency_list_export = dependency_list_export
      end

      def export_segment(part)
        exporter
          .new(dependency_list_export, part.sbom_occurrences)
          .generate_part { |f| part.file = f }

        part.file.filename = segment_filename(part.start_id, part.end_id)
        part.save!
      rescue StandardError => error
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(error)

        mark_as_failed!
      end

      def finalise_segmented_export
        exporter.combine_parts(partial_export_files) do |file|
          dependency_list_export.file = file
        end

        dependency_list_export.file.filename = final_export_filename
        dependency_list_export.store_file_now!
        dependency_list_export.finish!
        dependency_list_export.send_completion_email!
        dependency_list_export.schedule_export_deletion
      rescue StandardError => error
        Gitlab::ErrorTracking.track_and_raise_for_dev_exception(error)

        mark_as_failed!
      end

      private

      attr_reader :dependency_list_export

      delegate :exportable, :export_parts, to: :dependency_list_export

      def exporter
        EXPORTERS[dependency_list_export.export_type.to_sym]
      end

      def mark_as_failed!
        dependency_list_export.failed!
        Dependencies::DestroyExportWorker.perform_in(1.hour, dependency_list_export.id)
      end

      def partial_export_files
        export_parts.map(&:file)
      end

      def final_export_filename
        [
          exportable.full_path.parameterize,
          '_dependencies_',
          Time.current.utc.strftime('%FT%H%M'),
          '.',
          file_extension
        ].join
      end

      def segment_filename(start_id, end_id)
        [
          exportable.full_path.parameterize,
          "_dependencies_segment_#{start_id}_to_#{end_id}",
          Time.current.utc.strftime('%FT%H%M'),
          '.',
          file_extension
        ].join
      end

      def file_extension
        case dependency_list_export.export_type
        when 'json_array'
          'json'
        when 'csv'
          'csv'
        end
      end
    end
  end
end
