# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountDistinctNamespacesWithProjectAiToolRulesMetric < DatabaseMetric
          operation :distinct_count, column: :namespace_id

          # namespace_id values span a >100M range, so the default 10k batch
          # size exceeds the batch counter's loop limit and returns -1.
          metric_options do
            {
              batch_size: 1_000_000
            }
          end

          relation { ::Ai::ToolRule.where.not(project_id: nil) }
        end
      end
    end
  end
end
