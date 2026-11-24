# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountDistinctTopLevelGroupsWithMavenVirtualRegistriesMetric < DatabaseMetric
          operation :distinct_count, column: :group_id

          relation { ::VirtualRegistries::Packages::Maven::Registry }
        end
      end
    end
  end
end
