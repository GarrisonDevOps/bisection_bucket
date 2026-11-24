# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class Iteration < Base
        def before_create
          return unless target_work_item.get_widget(:iteration)
          return unless target_work_item.namespace.licensed_feature_available?(:iterations)

          target_work_item.iteration = matching_iteration
        end

        def post_move_cleanup
          # skip for now as we do not actually clean up widget data yet
        end

        private

        def matching_iteration
          return unless work_item.sprint_id.present?

          iteration = IterationsFinder.new(current_user, iteration_finder_params).execute.first

          return unless iteration && Ability.allowed?(current_user, :read_iteration, iteration)

          iteration
        end

        def iteration_finder_params
          { parent: target_work_item.namespace, include_ancestors: true, id: work_item.sprint_id }
        end
      end
    end
  end
end
