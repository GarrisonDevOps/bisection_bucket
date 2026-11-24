# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsWithCustomizedScanProfiles < DatabaseMetric
          operation :distinct_count, column: 'project_id'

          relation do
            ::Security::ScanProfileProject
              .joins(:scan_profile)
              .where(security_scan_profiles: { gitlab_recommended: false })
          end
        end
      end
    end
  end
end
