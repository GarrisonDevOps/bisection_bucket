# frozen_string_literal: true

module Dependencies # rubocop:disable Gitlab/BoundedContexts -- This is an existing module
  module Export
    class SegmentCreatorService
      SEGMENTED_EXPORT_WORKERS = 20
      BATCH_SIZE = 25_000

      def self.execute(...)
        new(...).execute
      end

      def initialize(dependency_list_export)
        @dependency_list_export = dependency_list_export
      end

      def execute
        dependency_list_export.start!

        create_export_parts
        schedule_finalization_or_segment_exporter
      rescue StandardError
        dependency_list_export.reset_state!

        raise
      end

      private

      attr_reader :dependency_list_export

      delegate :exportable, :export_parts, to: :dependency_list_export, private: true

      def create_export_parts
        iterator.each_batch(of: BATCH_SIZE) do |batch|
          break if batch.load.empty?

          export_parts.create!(
            start_id: batch.first.id,
            end_id: batch.last.id,
            organization_id: exportable.organization_id)
        end
      end

      def schedule_finalization_or_segment_exporter
        segment_count == 0 ? schedule_export_finalization : schedule_segment_exporters
      end

      def schedule_export_finalization
        ::Gitlab::Export::SegmentedExportFinalisationWorker.perform_async(dependency_list_export.to_global_id)
      end

      def schedule_segment_exporters
        segments.each do |segment|
          ::Gitlab::Export::SegmentedExportWorker.perform_async(dependency_list_export.to_global_id, segment)
        end
      end

      def iterator
        Gitlab::Pagination::Keyset::Iterator.new(
          scope: sbom_occurrences,
          use_union_optimization: false
        )
      end

      def sbom_occurrences
        exportable.sbom_occurrences.order_traversal_ids_asc
      end

      # Segments are array of export part IDs.
      # Each segment is handled by a separate Sidekiq job.
      def segments
        export_parts.map(&:id).in_groups(segment_count, false)
      end

      def segment_count
        @segment_count ||= [export_parts.length, SEGMENTED_EXPORT_WORKERS].min
      end
    end
  end
end
