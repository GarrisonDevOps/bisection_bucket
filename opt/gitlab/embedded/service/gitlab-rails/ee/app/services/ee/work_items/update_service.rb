# frozen_string_literal: true

module EE
  module WorkItems
    module UpdateService
      extend ::Gitlab::Utils::Override
      include ::WorkItems::SyncAsEpic

      override :execute
      def execute(work_item)
        if params_include_state_and_status_changes?
          return error('State event and status widget cannot be changed at the same time', :bad_request)
        end

        super
      end

      override :handle_changes
      def handle_changes(work_item, options)
        super

        return unless work_item.epic_work_item?

        epic = work_item&.synced_epic
        return unless epic

        old_associations = options.fetch(:old_associations, {})
        old_labels = old_associations.fetch(:labels, [])
        old_assignees = old_associations.fetch(:assignees, [])

        return unless has_changes?(epic, old_labels: old_labels, old_assignees: old_assignees)

        todo_service.resolve_todos_for_target(epic, current_user)
      end

      override :transaction_update_task
      def transaction_update_task(work_item)
        super.tap do |save_result|
          break save_result unless save_result

          update_epic_for!(work_item) if work_item.epic_work_item?
        end
      end

      private

      attr_reader :widget_params, :callbacks

      def transaction_update(work_item, opts = {})
        return super unless work_item.group_epic_work_item?

        super.tap do |save_result|
          break save_result unless save_result

          update_epic_for!(work_item)
        end
      end
    end
  end
end
