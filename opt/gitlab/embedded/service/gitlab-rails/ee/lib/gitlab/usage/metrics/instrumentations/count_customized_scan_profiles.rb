# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountCustomizedScanProfiles < DatabaseMetric
          operation :count

          relation { ::Security::ScanProfile.by_gitlab_recommended(false) }
        end
      end
    end
  end
end
