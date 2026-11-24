# frozen_string_literal: true

module Sbom
  class SyncArchivedStatusWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :always
    feature_category :dependency_management
    idempotent!

    def handle_event(event)
      ::Sbom::SyncArchivedStatusService.new(event.data['project_id']).execute
    end
  end
end
