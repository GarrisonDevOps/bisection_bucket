# frozen_string_literal: true

module Search
  module Elastic
    module Aggregations
      LABEL_AGGREGATION_LIMIT = 500
      WORK_ITEM_TYPE_AGGREGATION_LIMIT = 50

      class << self
        def by_label_ids(query_hash:, options: {}, max_size: LABEL_AGGREGATION_LIMIT)
          return query_hash unless options[:aggregation]

          query_hash.deep_merge(
            size: 0,
            aggs: {
              'labels' => {
                terms: {
                  field: 'label_ids',
                  size: max_size
                }
              }
            }
          )
        end

        # Opt-in via :state_aggregation rather than the generic :aggregation, because a
        # caller that wants per-state counts also needs Filters.by_state skipped for the
        # buckets to be meaningful. state is a low-cardinality keyword field
        # (opened/closed for work items), so it needs no size cap constant.
        def by_state(query_hash:, options: {})
          return query_hash unless options[:state_aggregation]

          query_hash.deep_merge(
            size: 0,
            aggs: {
              'state' => {
                terms: {
                  field: 'state'
                }
              }
            }
          )
        end

        def by_work_item_type_ids(query_hash:, options: {}, max_size: WORK_ITEM_TYPE_AGGREGATION_LIMIT)
          return query_hash unless options[:aggregation]

          query_hash.deep_merge(
            size: 0,
            aggs: {
              'work_item_type_ids' => {
                terms: {
                  field: 'work_item_type_id',
                  size: max_size
                }
              }
            }
          )
        end
      end
    end
  end
end
