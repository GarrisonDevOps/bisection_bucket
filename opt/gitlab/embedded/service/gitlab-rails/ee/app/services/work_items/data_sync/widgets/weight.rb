# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class Weight < Base
        def before_create
          return unless target_work_item.get_widget(:weight)

          target_work_item.weight = work_item.weight
        end

        def after_create
          return unless target_work_item.get_widget(:weight)
          return unless work_item.weights_source

          target_work_item.weights_source = WorkItems::WeightsSource.new(
            work_item.weights_source.attributes.except('namespace_id', 'work_item_id')
          )
        end

        def post_move_cleanup
          # The weight is a field in the work_item record, it will be removed upon the work_item deletion

          work_item.weights_source&.destroy!
        end
      end
    end
  end
end
