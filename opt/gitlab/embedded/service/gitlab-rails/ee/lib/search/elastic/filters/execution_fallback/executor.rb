# frozen_string_literal: true

module Search
  module Elastic
    module Filters
      module ExecutionFallback
        # Orchestrates Elasticsearch filter fallback using enrichment-based
        # post-processing, leveraging a Composer-built enrichment registry.
        #
        # When the `:elastic_filters_execution_fallback` feature flag is enabled,
        # this class:
        #
        # 1. Separates fallback filter arguments from native Elasticsearch query arguments
        #    by inspecting the ENRICHMENTS registry built via Enrichments::Composer.
        # 2. Overfetches results to preserve pagination density.
        # 3. Applies enrichment-based filtering in batches.
        # 4. Trims the final result set to the requested window.
        #
        # Enrichments are composed using Enrichments::Composer, which provides
        # an ordered ENRICHMENTS constant. Each enrichment module is responsible for:
        #
        #   - Defining filter methods (e.g., `false_positive(ids)`)
        #   - Optionally defining `normalize_filter(value)`
        #   - Returning a hash in the form: { record_id => value }
        #
        # Supports both:
        #   - Cursor pagination (first/last)
        #   - Offset pagination (page/per_page)
        #
        # Guarantees:
        #   - No behavior change when the feature flag is disabled.
        #   - Unknown filters are ignored.
        #   - Result size is capped by DEFAULT_RESULT_MAX_RECORDS.
        #   - Enrichment methods are executed in batches for safety.
        #
        # This abstraction allows shipping filters before ES implementation,
        # enabling safer rollout, decoupled filter evolution, and easier testing.
        class Executor
          BATCH_SIZE = 100

          DEFAULT_RESULT_MAX_RECORDS = 500
          DEFAULT_PAGINATION_OVERFETCH_WINDOW = 3

          class << self
            def fetch_with_fallback(
              args,
              user:,
              namespace:,
              result_max_records: DEFAULT_RESULT_MAX_RECORDS,
              pagination_overfetch_window: DEFAULT_PAGINATION_OVERFETCH_WINDOW
            )
              return yield(args) unless user.is_a?(::User)
              return yield(args) unless ::Feature.enabled?(:elastic_filters_execution_fallback, user)

              enrichments = namespace::ENRICHMENTS

              fallback_args = args.select do |key, _|
                enrichments.any? { |e| e.respond_to?(key) }
              end

              query_args = args.except(*fallback_args.keys)

              return yield(args) if fallback_args.empty?

              pagination = extract_pagination(args)

              query_args =
                expand_page_size(
                  query_args,
                  pagination,
                  result_max_records,
                  pagination_overfetch_window
                )

              result = yield(query_args)

              apply_fallback(
                result: result,
                fallback_args: fallback_args,
                namespace: namespace,
                result_max_records: result_max_records,
                pagination: pagination
              )
            end

            private

            def extract_pagination(args)
              if args[:first] || args[:last]
                {
                  limit: args[:first] || args[:last],
                  offset: 0
                }
              elsif args[:per_page]
                per_page = args[:per_page].to_i
                page     = (args[:page] || 1).to_i

                {
                  limit: per_page,
                  offset: (page - 1) * per_page
                }
              else
                { limit: nil, offset: 0 }
              end
            end

            def expand_page_size(query_args, pagination, result_max_records, overfetch_window)
              limit  = pagination[:limit]
              offset = pagination[:offset]

              return query_args unless limit

              requested = (limit + offset) * overfetch_window
              bounded   = [requested, result_max_records].min

              if query_args.key?(:first) || query_args.key?(:last)
                query_args.merge(first: bounded)
              elsif query_args.key?(:per_page)
                query_args.merge(per_page: bounded, page: 1)
              else
                query_args
              end
            end

            def apply_fallback(
              result:,
              fallback_args:,
              namespace:,
              result_max_records:,
              pagination:
            )
              records = Array(result.to_a).first(result_max_records)
              return records if records.empty?

              ids = records.map(&:id)
              enrichments = namespace::ENRICHMENTS

              value_maps, normalized_expected =
                build_enrichment_maps(ids, fallback_args, enrichments)

              allowed_ids =
                intersect_allowed_ids(
                  fallback_args.keys,
                  value_maps,
                  normalized_expected
                )

              filtered = records.select { |record| allowed_ids.include?(record.id) }

              trim_to_requested_window(filtered, pagination)
            end

            def build_enrichment_maps(ids, fallback_args, enrichments)
              value_maps = {}
              normalized_expected = {}

              fallback_args.each do |key, expected|
                enrichment = resolve_enrichment(key, enrichments)

                value_maps[key] =
                  build_value_map(ids, enrichment.method(key))

                normalized_expected[key] =
                  if enrichment.respond_to?(:normalize_filter)
                    enrichment.normalize_filter(expected)
                  else
                    expected
                  end
              end

              [value_maps, normalized_expected]
            end

            def intersect_allowed_ids(keys, value_maps, normalized_expected)
              keys
                .map do |key|
                expected_values = Array(normalized_expected[key])

                value_maps[key]
                  .select { |_id, value| expected_values.include?(value) }
                  .keys
                  .to_set
              end
                .reduce(:&) || Set.new
            end

            def resolve_enrichment(key, enrichments)
              enrichments.find { |e| e.respond_to?(key) } ||
                raise(ArgumentError, "Unknown fallback filter: #{key}")
            end

            def build_value_map(ids, enrichment_method)
              value_map = {}

              ids.each_slice(BATCH_SIZE) do |batch|
                value_map.merge!(enrichment_method.call(batch))
              end

              ids.index_with { |id| value_map[id] }
            end

            def trim_to_requested_window(records, pagination)
              limit  = pagination[:limit]
              offset = pagination[:offset]

              return records unless limit

              records.slice(offset, limit) || []
            end
          end
        end
      end
    end
  end
end
