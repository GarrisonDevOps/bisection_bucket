# frozen_string_literal: true

module WorkItems
  module Weights
    class UpdateWeightsService
      attr_reader :work_items

      def initialize(work_items)
        @work_items = Array.wrap(work_items)
      end

      def execute
        work_items.each do |work_item|
          WorkItems::WeightsSource.upsert_rolled_up_weights_for(work_item)

          work_item.ancestors.each do |ancestor|
            WorkItems::WeightsSource.upsert_rolled_up_weights_for(ancestor)
          end
        end
      end
    end
  end
end
