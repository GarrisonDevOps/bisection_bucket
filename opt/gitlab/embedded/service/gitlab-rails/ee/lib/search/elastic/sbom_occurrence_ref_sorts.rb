# frozen_string_literal: true

module Search
  module Elastic
    module SbomOccurrenceRefSorts
      TIE_BREAKER = :sbom_occurrence_id

      # Every field here must be occurrence-level, never ref-level: the query collapses on
      # TIE_BREAKER, so Elasticsearch sorts on one arbitrarily chosen document per occurrence and a
      # ref-level field would order the page by whichever ref happened to be picked.
      SORT_FIELDS = {
        'severity' => :highest_severity,
        'highest_severity' => :highest_severity,
        'packager' => :package_manager,
        'package_manager' => :package_manager,
        'name' => :component_name,
        'component_name' => :component_name,
        'license' => :primary_license_spdx_identifier,
        'primary_license_spdx_identifier' => :primary_license_spdx_identifier
      }.freeze

      class << self
        def sort_by(query_hash:, options:)
          query_hash.merge(sort: build_sort(options))
        end

        def sort_direction(options)
          options[:sort].to_s.casecmp?('desc') ? :desc : :asc
        end

        private

        def build_sort(options)
          field = SORT_FIELDS[options[:sort_by].to_s]
          return { TIE_BREAKER => { order: :asc } } unless field

          { field => { order: sort_direction(options) }, TIE_BREAKER => { order: :asc } }
        end
      end
    end
  end
end
