# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      # Updates the `vulnerability_id` attribute of FindingEnrichment records
      # for findings that are associated with vulnerabilities.
      class UpdateFindingEnrichmentVulnerabilities < AbstractTask
        include Gitlab::Ingestion::BulkUpdatableTask

        self.model = Security::FindingEnrichment

        private

        def attributes
          return [] if finding_map_data.empty?

          finding_enrichments_for_uuids.map do |(uuid, id)|
            vulnerability_id = finding_map_data[uuid]

            { id: id, vulnerability_id: vulnerability_id }
          end
        end

        def finding_enrichments_for_uuids
          @finding_enrichments_for_uuids ||= Security::FindingEnrichment
            .for_finding_uuids(finding_map_data.keys)
            .pluck(:finding_uuid, :id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- Bounded by finding_maps batch size, specific to this task
        end

        def finding_map_data
          @finding_map_data ||= finding_maps
            .select { |fm| fm.new_record && fm.vulnerability_id.present? }
            .to_h { |fm| [fm.uuid, fm.vulnerability_id] }
        end
      end
    end
  end
end
