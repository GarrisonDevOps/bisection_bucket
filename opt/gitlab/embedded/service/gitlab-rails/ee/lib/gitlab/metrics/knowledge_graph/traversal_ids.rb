# frozen_string_literal: true

module Gitlab
  module Metrics
    module KnowledgeGraph
      module TraversalIds
        TRAVERSAL_IDS_COUNT = :gitlab_knowledge_graph_traversal_ids_count
        COMPACTION_RATIO = :gitlab_knowledge_graph_compaction_ratio
        COMPACTION_FALLBACK_TOTAL = :gitlab_knowledge_graph_compaction_fallback_total
        THRESHOLD_EXCEEDED_TOTAL = :gitlab_knowledge_graph_traversal_ids_threshold_exceeded_total

        COUNT_BUCKETS = [10, 50, 100, 250, 500, 1000, 2500, 5000].freeze
        RATIO_BUCKETS = [0.01, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0].freeze

        class << self
          def observe_traversal_ids_count(count)
            traversal_ids_count_histogram.observe({}, count)
          end

          def observe_compaction_ratio(ratio)
            compaction_ratio_histogram.observe({}, ratio)
          end

          def increment_compaction_fallback
            compaction_fallback_counter.increment({})
          end

          def increment_threshold_exceeded
            threshold_exceeded_counter.increment({})
          end

          private

          def traversal_ids_count_histogram
            ::Gitlab::Metrics.histogram(
              TRAVERSAL_IDS_COUNT,
              'Distribution of traversal ID counts before compaction',
              {},
              COUNT_BUCKETS
            )
          end

          def compaction_ratio_histogram
            ::Gitlab::Metrics.histogram(
              COMPACTION_RATIO,
              'Ratio of compacted to original traversal ID count',
              {},
              RATIO_BUCKETS
            )
          end

          def compaction_fallback_counter
            ::Gitlab::Metrics.counter(
              COMPACTION_FALLBACK_TOTAL,
              'Number of times traversal ID compaction fell back to truncation'
            )
          end

          def threshold_exceeded_counter
            ::Gitlab::Metrics.counter(
              THRESHOLD_EXCEEDED_TOTAL,
              'Number of times traversal ID count exceeded the threshold'
            )
          end
        end
      end
    end
  end
end
