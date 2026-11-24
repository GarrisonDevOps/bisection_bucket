# frozen_string_literal: true

module Search
  module Elastic
    module SbomOccurrenceRefAggregations
      class << self
        include ::Elastic::Latest::QueryContext::Aware

        DEFAULT_BUCKET_SIZE = 20
        # Elasticsearch's own default, set here so it is a decision rather than a default that
        # can drift. Counts turn approximate above it; 40_000 is the ceiling and costs more
        # memory per shard.
        CARDINALITY_PRECISION_THRESHOLD = 3_000

        # Format - { field_name: field_nullable_or_not }
        DEFAULT_SORT_SOURCES = { component_id: false, component_version_id: true }.freeze

        def by_component_and_version(query_hash:, options:)
          return query_hash unless options[:aggregate_by_component_and_version]

          context.name(:aggregations) do
            query_hash.merge(
              size: 0,
              aggs: {
                dependencies: {
                  composite: composite(options),
                  # Only used to hydrate the record from Postgres.
                  aggs: { occurrence_id: { min: { field: :sbom_occurrence_id } } }
                }
              }
            )
          end
        end

        def by_version_counts(query_hash:, options:)
          pairs_by_name = component_and_version_filters(options)
          return query_hash if pairs_by_name.blank?

          context.name(:aggregations) do
            query_hash.merge(
              size: 0,
              aggs: {
                version_counts: {
                  filters: { filters: dependency_filters(pairs_by_name) },
                  aggs: {
                    occurrence_count: { cardinality: { field: :sbom_occurrence_id,
                                                       precision_threshold: CARDINALITY_PRECISION_THRESHOLD } },
                    project_count: { cardinality: { field: :project_id,
                                                    precision_threshold: CARDINALITY_PRECISION_THRESHOLD } },
                    vulnerability_count: { sum: { field: :vulnerability_count } }
                  }
                }
              }
            )
          end
        end

        private

        def component_and_version_filters(options)
          options[:component_and_version_filters]
        end

        def dependency_filters(pairs_by_name)
          pairs_by_name.transform_values do |(component_id, component_version_id)|
            version_filter = if component_version_id.nil?
                               { bool: { must_not: { exists: { field: :component_version_id } } } }
                             else
                               { term: { component_version_id: component_version_id } }
                             end

            { bool: { filter: [{ term: { component_id: component_id } }, version_filter] } }
          end
        end

        def composite(options)
          composite = { size: bucket_size(options), sources: sources(options) }
          after_key = options[:after_key]
          composite[:after] = after_key if after_key.present?

          composite
        end

        def sources(options)
          order = SbomOccurrenceRefSorts.sort_direction(options)
          sort_field = SbomOccurrenceRefSorts::SORT_FIELDS[options[:sort_by].to_s]
          sources = DEFAULT_SORT_SOURCES
          # The sort field must come first so that the buckets are ordered by it.
          sources = { sort_field => true, **sources } if sort_field

          sources.map do |field, missing_bucket|
            terms = { field: field, order: order }
            terms[:missing_bucket] = missing_bucket
            missing = missing_order(field, order) if missing_bucket
            terms[:missing_order] = missing if missing

            { field => { terms: terms } }
          end
        end

        # Elasticsearch's default placement already matches the nulls_last-on-descending that
        # ::Sbom::AggregationsFinder#nullable applies to highest_severity alone.
        def missing_order(field, order)
          return if field == :highest_severity

          order == :asc ? :last : :first
        end

        def sort_direction(options)
          options[:sort].to_s.casecmp?('desc') ? :desc : :asc
        end

        def bucket_size(options)
          (options[:bucket_size].presence || DEFAULT_BUCKET_SIZE).to_i.clamp(1..)
        end
      end
    end
  end
end
