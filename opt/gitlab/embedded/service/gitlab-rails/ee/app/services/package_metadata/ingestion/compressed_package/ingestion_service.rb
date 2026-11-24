# frozen_string_literal: true

module PackageMetadata
  module Ingestion
    module CompressedPackage
      class IngestionService
        def self.execute(import_data)
          new(import_data).execute
        end

        def initialize(import_data)
          @import_data = import_data
          @identifier_map = {}
          @expression_map = {}
        end

        # V3SyncService reads this as "was the slice persisted" to decide whether to
        # advance a checkpoint, so return a Boolean rather than the transaction's value.
        def execute
          ApplicationRecord.transaction do
            ingest_licenses
            ingest_packages
          end

          true
        end

        private

        def ingest_licenses
          LicenseIngestionTask.execute(import_data, identifier_map, expression_map)
        end

        def ingest_packages
          PackageIngestionTask.execute(import_data, identifier_map, expression_map)
        end

        attr_reader :import_data, :identifier_map, :expression_map
      end
    end
  end
end
