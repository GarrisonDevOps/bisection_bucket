# frozen_string_literal: true

module Sbom
  module Ingestion
    module ExecutionStrategy
      class ContainerScanningForRegistry < Default
        def execute
          ingest_reports

          delete_not_present_occurrences

          publish_ingested_sbom_event
        end

        private

        attr_reader :ingested_source_id

        def ingest_reports
          # At present we only have one source_id for all occurrences.
          @ingested_source_id = super.dig(0, :source_ids)&.first
        end

        def delete_not_present_occurrences
          Sbom::Ingestion::ContainerScanningForRegistry::DeleteNotPresentOccurrencesService.execute(
            pipeline, ingested_ids, ingested_source_id)
        end
      end
    end
  end
end
