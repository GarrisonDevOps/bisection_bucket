# frozen_string_literal: true

module WorkItems
  module Weights
    class UpdateWeightsWorker
      include ApplicationWorker

      data_consistency :delayed
      feature_category :team_planning
      concurrency_limit -> { 100 }
      idempotent!

      def perform(work_item_ids)
        work_item_ids = Array.wrap(work_item_ids)
        work_items = ::WorkItem.id_in(work_item_ids)
        return if work_items.blank?

        UpdateWeightsService.new(work_items).execute
      end
    end
  end
end
