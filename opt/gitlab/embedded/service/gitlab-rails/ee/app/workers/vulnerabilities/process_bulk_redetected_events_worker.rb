# frozen_string_literal: true

module Vulnerabilities
  # Ingest bulk redetected events to enqueue insertion of notes.

  class ProcessBulkRedetectedEventsWorker
    include Gitlab::EventStore::Subscriber

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :vulnerability_management

    def handle_event(event)
      Vulnerabilities::BulkCreateRedetectedNotesService.new(event.data[:vulnerabilities]).execute
    end
  end
end
