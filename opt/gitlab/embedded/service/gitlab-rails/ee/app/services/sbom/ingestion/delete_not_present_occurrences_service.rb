# frozen_string_literal: true

module Sbom
  module Ingestion
    class DeleteNotPresentOccurrencesService
      include Gitlab::Utils::StrongMemoize

      DELETE_BATCH_SIZE = 100

      def self.execute(...)
        new(...).execute
      end

      def initialize(pipeline, ingested_occurrence_ids)
        @pipeline = pipeline
        @ingested_occurrence_ids = ingested_occurrence_ids
      end

      def execute
        return if has_failed_sbom_jobs?

        vulnerability_ids = collect_vulnerability_ids_and_delete_occurrences
        ::Vulnerabilities::EsHelper.sync_elasticsearch(vulnerability_ids)
      end

      private

      attr_reader :pipeline, :ingested_occurrence_ids

      delegate :project, to: :pipeline, private: true

      def has_failed_sbom_jobs?
        # rubocop:disable CodeReuse/ActiveRecord -- This logic is specific to this service
        pipeline.builds.preload(:job_definition).failed.find_each(batch_size: 100).any? { |b| sbom_build?(b) }
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def sbom_build?(build)
        build.options.dig(:artifacts, :reports, :cyclonedx).present?
      end

      def default_source_type_filters
        ::Sbom::Source::DEFAULT_SOURCES.keys + [nil]
      end

      def collect_vulnerability_ids_and_delete_occurrences
        vulnerability_ids = []

        not_present_occurrences.each_batch(of: DELETE_BATCH_SIZE) do |occurrences|
          delete_occurrence_refs(occurrences)

          occurrences_to_delete = occurrences.ref_orphaned.pluck_primary_key

          vulnerability_ids += extract_vulnerability_ids(occurrences_to_delete)
          delete_occurrences(occurrences_to_delete)
        end

        vulnerability_ids.uniq.compact
      end

      def not_present_occurrences
        project.sbom_occurrences.filter_by_source_types(default_source_type_filters).id_not_in(ingested_occurrence_ids)
      end

      def delete_occurrence_refs(occurrences)
        deleted_rows = Sbom::OccurrenceRef
          .by_tracked_context(tracked_context.id)
          .by_occurrence(occurrences.select(:id))
          .delete_all_returning(:id)

        track_elasticsearch_deletes(deleted_rows.pluck('id')) # rubocop:disable CodeReuse/ActiveRecord,Database/AvoidUsingPluckWithoutLimit -- not activereocrd pluck
      end

      def track_elasticsearch_deletes(ids)
        return if ids.empty?
        return unless ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed?

        es_parent = Sbom::OccurrenceRef.generate_es_parent(project)
        refs = ids.map { |id| ::Search::Elastic::References::Sbom::OccurrenceRef.new(id, es_parent) }

        ::Elastic::ProcessBookkeepingService.track!(*refs)
      end

      def tracked_context
        response = ::Security::ProjectTrackedContexts::FindOrCreateService.from_pipeline(pipeline).execute!

        if response.error?
          raise "Failed to find or create tracked context for project #{project.id}: #{response.errors.join(',')}"
        end

        response.payload[:tracked_context]
      end
      strong_memoize_attr :tracked_context

      def extract_vulnerability_ids(occurrence_ids)
        Sbom::OccurrencesVulnerability
          .for_occurrence_ids(occurrence_ids)
          .pluck(:vulnerability_id) # rubocop:disable CodeReuse/ActiveRecord,Database/AvoidUsingPluckWithoutLimit -- only need vulnerability ids and its limited to a small batch
      end

      def delete_occurrences(occurrence_ids)
        Sbom::Occurrence.id_in(occurrence_ids).delete_all
      end
    end
  end
end
