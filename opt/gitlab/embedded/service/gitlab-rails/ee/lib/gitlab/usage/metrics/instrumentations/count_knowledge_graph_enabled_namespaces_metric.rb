# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountKnowledgeGraphEnabledNamespacesMetric < DatabaseMetric
          operation :count

          relation { ::Analytics::KnowledgeGraph::EnabledNamespace }
        end
      end
    end
  end
end
