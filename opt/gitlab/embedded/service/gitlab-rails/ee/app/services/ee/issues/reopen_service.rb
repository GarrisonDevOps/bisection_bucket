# frozen_string_literal: true

module EE
  module Issues
    module ReopenService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      private

      override :perform_incident_management_actions
      def perform_incident_management_actions(issue)
        super
        update_issuable_sla(issue)
      end

      attr_reader :work_item

      override :reopen_issue
      def reopen_issue(issue)
        set_work_item(issue)

        return super unless work_item.synced_epic
        # In case the epic and work item went out of sync but the epic is open, we don't want to error but just return.
        return super if work_item.synced_epic.open?

        ApplicationRecord.transaction do
          work_item.synced_epic.reopen! if super
        end
      rescue StandardError => error
        ::Gitlab::EpicWorkItemSync::Logger.error(
          message: "Not able to sync reopening epic work item",
          error_message: error.message,
          work_item_id: issue.id)

        ::Gitlab::ErrorTracking.track_and_raise_exception(error, work_item_id: issue.id)
      end

      # rubocop:disable Gitlab/ModuleWithInstanceVariables -- this module is an extension of a service
      def set_work_item(issue)
        @work_item = case issue
                     when WorkItem
                       issue
                     else
                       ::WorkItem.find(issue.id)
                     end
      end
      # rubocop:enable Gitlab/ModuleWithInstanceVariables

      def after_reopen(issue, status)
        old_associations = status.nil? ? status_change_associations(issue) : {}

        ::Gitlab::EventStore.publish(
          ::WorkItems::WorkItemReopenedEvent.new(data: {
            id: issue.id,
            namespace_id: issue.namespace_id
          })
        )
        update_status_after_state_change(issue, status)

        super(issue, status, old_associations: old_associations)

        # Creating a system note changes `updated_at` for the issue
        work_item.synced_epic&.update_column(:updated_at, issue.updated_at)
      end
    end
  end
end
