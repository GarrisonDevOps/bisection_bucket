# frozen_string_literal: true

module API
  module Entities
    module Analytics
      module GroupActivity
        class NewMembersCount < Grape::Entity
          expose :new_members_count, documentation: {
            type: "Integer",
            desc: "Number of new members. Limited to #{::Analytics::GroupActivityCalculator::RECENT_COUNT_LIMIT}. " \
              "`null` when `too_large` is `true`.",
            example: 3
          } do |calculator|
            calculator.new_members_count unless calculator.too_large?(:new_members)
          end
          expose :too_large,
            if: ->(calculator, _options) { calculator.too_large?(:new_members) },
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
