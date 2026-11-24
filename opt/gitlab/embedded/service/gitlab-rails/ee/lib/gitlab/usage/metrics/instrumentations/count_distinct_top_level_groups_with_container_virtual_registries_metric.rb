# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountDistinctTopLevelGroupsWithContainerVirtualRegistriesMetric < DatabaseMetric
          operation :distinct_count, column: :group_id

          relation { ::VirtualRegistries::Container::Registry }
        end
      end
    end
  end
end
