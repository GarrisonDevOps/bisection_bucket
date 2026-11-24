# frozen_string_literal: true

module API
  module Entities
    module Analytics
      module GroupActivity
        class MergeRequestsCount < Grape::Entity
          expose :merge_requests_count, documentation: {
            type: "Integer",
            desc: "Number of merge requests. Limited to #{::Analytics::GroupActivityCalculator::RECENT_COUNT_LIMIT}. " \
              "`null` when `too_large` is `true`.",
            example: 3
          } do |calculator|
            calculator.merge_requests_count unless calculator.too_large?(:merge_requests)
          end
          expose :too_large,
            if: ->(calculator, _options) { calculator.too_large?(:merge_requests) },
            documentation: {
              type: "Boolean",
              desc: "Present and `true` when the count could not be calculated within the time limit. " \
                "The count is then unknown and `null`.",
              example: true
            } do |_calculator|
            true
          end
        end
      end
    end
  end
end
