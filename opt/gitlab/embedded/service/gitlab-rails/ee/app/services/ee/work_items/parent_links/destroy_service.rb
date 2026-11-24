# frozen_string_literal: true

module EE
  module WorkItems
    module ParentLinks
      module DestroyService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        def execute
          super
        rescue ::WorkItems::SyncAsEpic::SyncAsEpicError => error
          ::Gitlab::ErrorTracking.track_exception(error, work_item_parent_id: parent.id)

          error(_("Couldn't delete link due to an internal error."), 422)
        end

        private

        def remove_relation
          return super if synced_work_item?
          return super unless parent.group_epic_work_item?
          return super unless parent.synced_epic.present?

          ::ApplicationRecord.transaction do
            destroy_parent_link = super
            sync_to_work_item! if destroy_parent_link
          end
        end

        def sync_to_work_item!
          return unless child.group_epic_work_item?

          service_response = handle_epic_link
          return if service_response[:status] == :success

          ::Gitlab::EpicWorkItemSync::Logger.error(
            message: 'Not able to remove work item parent link',
            error_message: service_response[:message],
            namespace_id: parent.namespace.id,
            work_item_id: child.id,
            work_item_parent_id: parent.id
          )
          raise ::WorkItems::SyncAsEpic::SyncAsEpicError, service_response[:message]
        end

        override :create_notes
        def create_notes
          return if synced_work_item?

          super
        end

        override :permission_to_remove_relation?
        def permission_to_remove_relation?
          return true if synced_work_item?

          if parent.work_item_type.epic? && child.work_item_type.epic? &&
              !parent.namespace.licensed_feature_available?(:subepics)
            return false
          end

          super
        end

        def synced_work_item?
          params.fetch(:synced_work_item, false)
        end

        def handle_epic_link
          return { status: :success } unless child.synced_epic&.parent.present?

          child.synced_epic.update!(parent_id: nil)

          { status: :success }
        end
      end
    end
  end
end
