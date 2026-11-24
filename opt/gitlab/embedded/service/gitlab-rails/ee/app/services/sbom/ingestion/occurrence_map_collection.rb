# frozen_string_literal: true

module Sbom
  module Ingestion
    class OccurrenceMapCollection
      include Enumerable
      include Gitlab::Utils::StrongMemoize

      def initialize(pipeline, sbom_report)
        @pipeline = pipeline
        @sbom_report = sbom_report
      end

      def each
        return to_enum(:each) unless block_given?

        sbom_report.components.sort.each do |report_component|
          yield OccurrenceMap.new(report_component, sbom_report.source, tracked_context)
        end
      end

      private

      attr_reader :pipeline, :sbom_report

      def tracked_context
        response = ::Security::ProjectTrackedContexts::FindOrCreateService.from_pipeline(pipeline).execute!

        if response.error?
          raise "Failed to find or create tracked context for project #{pipeline.project.id}: " \
            "#{response.errors.join(',')}"
        end

        response.payload[:tracked_context]
      end
      strong_memoize_attr :tracked_context
    end
  end
end
