# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountRelatedEpicLinksMetric < DatabaseMetric
          operation :count

          relation { ::Epic::RelatedEpicLink }
        end
      end
    end
  end
end
