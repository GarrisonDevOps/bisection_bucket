# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      # Links findings with identifiers by creating the
      # `Vulnerabilities::FindingIdentifier` records.
      class IngestFindingIdentifiers < AbstractTask
        include Gitlab::Ingestion::BulkInsertableTask

        self.model = Vulnerabilities::FindingIdentifier
        self.unique_by = %i[occurrence_id identifier_id].freeze
        # The unique key is the whole row, so a conflicting insert has nothing to update.
        # DO UPDATE was rewriting ~2.1M unchanged rows an hour and taking an exclusive lock
        # on each one until the slice transaction committed.
        self.on_conflict = :nothing

        private

        def attributes
          finding_maps.flat_map do |finding_map|
            finding_map.identifier_ids.map do |identifier_id|
              {
                occurrence_id: finding_map.finding_id,
                identifier_id: identifier_id
              }
            end
          end
        end
      end
    end
  end
end
