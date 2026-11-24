# frozen_string_literal: true

module PackageMetadata
  module Ingestion
    module CveEnrichment
      class IngestionService
        def self.execute(import_data)
          new(import_data).execute
        end

        def initialize(import_data)
          @import_data = import_data
        end

        def execute
          CveEnrichmentIngestionTask.new(@import_data).execute
        end
      end
    end
  end
end
