# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountEpicsWithParentsMetric < DatabaseMetric
          operation :count

          relation { Epic.where.not(parent_id: nil) }
        end
      end
    end
  end
end
