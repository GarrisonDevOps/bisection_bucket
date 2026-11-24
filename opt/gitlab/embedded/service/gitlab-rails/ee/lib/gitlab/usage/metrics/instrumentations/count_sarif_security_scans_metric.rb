# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountSarifSecurityScansMetric < DatabaseMetric
          operation :count, column: :build_id

          start { ::Security::Scan.sarif_derived.minimum(:build_id) }
          finish { ::Security::Scan.sarif_derived.maximum(:build_id) }
          metric_options do
            {
              batch_size: 1_000_000
            }
          end

          relation { ::Security::Scan.sarif_derived }
        end
      end
    end
  end
end
