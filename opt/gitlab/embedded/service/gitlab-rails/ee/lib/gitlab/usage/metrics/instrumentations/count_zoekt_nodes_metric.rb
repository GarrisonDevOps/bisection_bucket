# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountZoektNodesMetric < DatabaseMetric
          operation :count

          relation { ::Search::Zoekt::Node.online }

          available? { ::License.feature_available?(:zoekt_code_search) }
        end
      end
    end
  end
end
