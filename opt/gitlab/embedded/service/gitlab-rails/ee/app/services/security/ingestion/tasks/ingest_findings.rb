# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class IngestFindings < AbstractTask
        include Gitlab::Ingestion::BulkInsertableTask
        include Vulnerabilities::DetailSanitizer

        self.model = Vulnerabilities::Finding
        self.unique_by = :uuid
        self.uses = %i[id vulnerability_id].freeze

        private

        def after_ingest
          return_data.each_with_index do |(finding_id, vulnerability_id), index|
            finding_map = finding_maps[index]

            finding_map.finding_id = finding_id
            finding_map.vulnerability_id = vulnerability_id
          end
        end

        def attributes
          finding_maps
            .map(&:to_hash)
            .map { |attrs| truncate_columns(attrs) }
            .map { |attrs| sanitize_details_in(attrs) }
        end

        # Important Note:
        #   Sorting the finding_maps by `uuid` (the ON CONFLICT key for the
        #   `vulnerability_occurrences` UPSERT) is important to prevent deadlock
        #   errors which can happen if other threads try to ingest the same
        #   findings in a different order. See gitlab-org/gitlab#603320.
        #
        #   We sort the underlying `finding_maps` array once (rather than only
        #   sorting the `attributes` hashes) because `after_ingest` maps the
        #   bulk_upsert `return_data` back to `finding_maps` by position/index.
        #   `bulk_upsert` preserves the order of the attributes array, and
        #   `attributes` derives from `finding_maps`, so both must iterate the
        #   same sorted order to keep the finding_id/vulnerability_id assignment
        #   aligned with the correct finding_map.
        def finding_maps
          @sorted_finding_maps ||= super.sort_by(&:uuid)
        end

        def truncate_columns(attrs)
          Vulnerabilities::Finding::COLUMN_LENGTH_LIMITS.each do |attr_name, limit|
            attrs[attr_name] = attrs[attr_name]&.truncate(limit)
          end
          attrs
        end

        def sanitize_details_in(attrs)
          return attrs if attrs[:details].blank?

          attrs[:details] = attrs[:details].transform_values do |detail|
            detail.is_a?(Hash) ? sanitize_detail(detail.with_indifferent_access) : detail
          end
          attrs
        end
      end
    end
  end
end
