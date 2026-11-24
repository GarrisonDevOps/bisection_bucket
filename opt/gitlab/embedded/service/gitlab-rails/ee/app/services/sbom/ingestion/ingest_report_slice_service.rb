# frozen_string_literal: true

module Sbom
  module Ingestion
    class IngestReportSliceService
      TASKS = [
        ::Sbom::Ingestion::Tasks::IngestComponents,
        ::Sbom::Ingestion::Tasks::IngestComponentVersions,
        ::Sbom::Ingestion::Tasks::IngestSources,
        ::Sbom::Ingestion::Tasks::IngestSourcePackages,
        ::Sbom::Ingestion::Tasks::IngestOccurrences,
        ::Sbom::Ingestion::Tasks::IngestOccurrenceRefs,
        ::Sbom::Ingestion::Tasks::IngestOccurrencesVulnerabilities,
        ::Sbom::Ingestion::Tasks::UpdateSecurityPolicyDismissals
      ].freeze

      def self.execute(pipeline, occurrence_maps)
        new(pipeline, occurrence_maps).execute
      end

      def initialize(pipeline, occurrence_maps)
        @pipeline = pipeline
        @occurrence_maps = occurrence_maps
      end

      def execute
        tasks.each { |task| task.execute(pipeline, occurrence_maps) }

        ::Sbom::Ingestion::TrackOccurrenceRefsEsService.execute(occurrence_maps)

        { occurrence_ids: occurrence_maps.map(&:occurrence_id), source_ids: occurrence_maps.map(&:source_id).uniq }
      end

      private

      attr_reader :pipeline, :occurrence_maps

      def tasks
        TASKS
      end
    end
  end
end
