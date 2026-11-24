# frozen_string_literal: true

module Sbom
  module Ingestion
    module ExecutionStrategy
      class Default
        attr_reader :reports, :project, :pipeline

        def initialize(reports, project, pipeline)
          @reports = reports
          @project = project
          @pipeline = pipeline
        end

        def execute
          ingest_reports

          set_latest_ingested_sbom_pipeline_id

          delete_not_present_occurrences

          publish_ingested_sbom_event
        end

        private

        attr_reader :ingested_ids

        def ingest_reports
          response = reports.flat_map do |report|
            ingest_report(report)
          end

          @ingested_ids = response.flat_map { |r| r[:occurrence_ids] }

          response
        end

        def ingest_report(sbom_report)
          IngestReportService.execute(pipeline, sbom_report)
        end

        def set_latest_ingested_sbom_pipeline_id
          project.set_latest_ingested_sbom_pipeline_id(pipeline.id)
        end

        def delete_not_present_occurrences
          DeleteNotPresentOccurrencesService.execute(pipeline, ingested_ids)
        end

        def publish_ingested_sbom_event
          return unless ingested_ids.present?

          Gitlab::EventStore.publish(
            Sbom::SbomIngestedEvent.new(data: { pipeline_id: pipeline.id })
          )
        end
      end
    end
  end
end
