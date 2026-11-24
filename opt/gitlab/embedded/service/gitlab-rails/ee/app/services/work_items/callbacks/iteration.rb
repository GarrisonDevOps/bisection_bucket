# frozen_string_literal: true

module WorkItems
  module Callbacks
    class Iteration < Base
      BATCH_SIZE = 100

      def before_create
        handle_iteration_change
      end

      def before_update
        params[:iteration] = nil if excluded_in_new_type?

        handle_iteration_change
      end

      def after_update_commit
        return unless work_item.sprint_id_previously_changed?

        previous_iteration_id = work_item.sprint_id_before_last_save

        handle_children_iteration_change(previous_iteration_id)
      end

      private

      def handle_iteration_change
        return unless params.present? && params.key?(:iteration)
        return unless has_permission?(:admin_work_item)

        if params[:iteration].nil?
          work_item.iteration = nil

          return
        end

        return unless in_the_same_group_hierarchy?(params[:iteration])

        work_item.iteration = params[:iteration]
      end

      def in_the_same_group_hierarchy?(iteration)
        group_ids = (work_item.project&.group || work_item.namespace).self_and_ancestors.select(:id)

        ::Iteration.of_groups(group_ids).id_in(iteration.id).exists?
      end

      def handle_children_iteration_change(previous_iteration_id)
        return unless work_item.get_widget(:iteration)

        descendant_ids = work_item.descendants.opened.select(:id)
        WorkItem
          .id_in(descendant_ids)
          .with_enabled_widget_definition(:iteration)
          .in_iterations(previous_iteration_id)
          .preload_iteration
          .each_batch(of: BATCH_SIZE) do |children_batch|
          resource_iteration_event_attributes = children_batch.filter_map do |child|
            previous_iteration = child.iteration
            child.iteration = work_item.iteration
            ::ResourceEvents::ChangeIterationService
              .new(
                child,
                current_user,
                old_iteration: previous_iteration,
                automated: true,
                triggered_by_work_item: work_item
              )
              .build_resource_args
          end

          children_batch.update_all(sprint_id: work_item.sprint_id)

          ResourceIterationEvent.insert_all(resource_iteration_event_attributes)
        end
      end
    end
  end
end
