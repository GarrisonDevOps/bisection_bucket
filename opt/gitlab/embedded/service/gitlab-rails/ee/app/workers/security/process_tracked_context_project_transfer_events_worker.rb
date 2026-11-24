# frozen_string_literal: true

module Security
  class ProcessTrackedContextProjectTransferEventsWorker
    include Gitlab::EventStore::Subscriber

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :vulnerability_management

    def handle_event(event)
      project_id = event.data[:project_id]

      return unless Security::ProjectTrackedContext.for_project(project_id).exists?

      ::Security::SyncTrackedContextTraversalIdsWorker.perform_async(project_id)
    end
  end
end
