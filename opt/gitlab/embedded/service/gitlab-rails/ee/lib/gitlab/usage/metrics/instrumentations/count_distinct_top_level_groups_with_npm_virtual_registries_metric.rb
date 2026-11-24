# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountDistinctTopLevelGroupsWithNpmVirtualRegistriesMetric < DatabaseMetric
          operation :distinct_count, column: :group_id

          relation { ::VirtualRegistries::Packages::Npm::Registry }
        end
      end
    end
  end
end
