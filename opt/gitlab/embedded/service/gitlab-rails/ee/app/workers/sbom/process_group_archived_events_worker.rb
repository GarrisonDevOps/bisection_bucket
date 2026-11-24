# frozen_string_literal: true

module Sbom
  class ProcessGroupArchivedEventsWorker
    include Gitlab::EventStore::Subscriber

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :dependency_management

    def handle_event(event)
      ::Sbom::SyncGroupArchivedStatusService.new(event.data[:group_id]).execute
    end
  end
end
