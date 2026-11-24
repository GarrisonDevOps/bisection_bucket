# frozen_string_literal: true

module Sbom
  module Ingestion
    module ContainerScanningForRegistry
      class DeleteNotPresentOccurrencesService < Sbom::Ingestion::DeleteNotPresentOccurrencesService
        def initialize(pipeline, ingested_occurrence_ids, ingested_source_id)
          super(pipeline, ingested_occurrence_ids)

          @ingested_source_id = ingested_source_id
        end

        private

        attr_reader :ingested_source_id

        def not_present_occurrences
          project.sbom_occurrences.filter_by_source_id(ingested_source_id).id_not_in(ingested_occurrence_ids)
        end
      end
    end
  end
end
