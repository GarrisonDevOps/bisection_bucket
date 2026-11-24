# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountRootNamespaceScanProfiles < DatabaseMetric
          operation :distinct_count, column: 'namespace_id'

          relation { ::Security::ScanProfile }
        end
      end
    end
  end
end
