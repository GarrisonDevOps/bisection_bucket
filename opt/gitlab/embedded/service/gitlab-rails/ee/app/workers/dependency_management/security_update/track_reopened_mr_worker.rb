# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Otherwise a close nobody meant suppresses the dependency until a higher
    # fix version appears.
    class TrackReopenedMrWorker
      include Gitlab::EventStore::Subscriber

      idempotent!

      feature_category :dependency_management
      data_consistency :sticky
      urgency :low
      deduplicate :until_executing, including_scheduled: true
      defer_on_database_health_signal :gitlab_sec, [:dependency_management_remediations], 1.minute

      def handle_event(event)
        merge_request = MergeRequest.find_by_id(event.data[:merge_request_id])

        # Jobs can run out of order, so a reopen that was closed again since must not
        # withdraw the newer dismissal.
        return unless merge_request&.open?

        ::DependencyManagement::Remediation.withdraw_dismissal_for_merge_request(merge_request)
      end
    end
  end
end
