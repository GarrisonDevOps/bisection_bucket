# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class ProcessAuditEventsWorker
      include ApplicationWorker

      # Each event carries a `cloud_event_id` UUID; storage uses `skip_duplicates: true`
      # and the ClickHouse write buffer is idempotent on that key, so retries are safe.
      idempotent!
      data_consistency :sticky
      feature_category :audit_events
      urgency :low
      sidekiq_options retry: 9
      defer_on_database_health_signal :gitlab_main, [:ai_audit_events]

      # @param serialized_events [Array<Hash>] Array of AR attribute hashes for unsaved
      #   AuditEvents::AiAuditEvent objects, produced by the service before enqueuing.
      def perform(serialized_events)
        return if serialized_events.blank?

        audit_events = serialized_events.map { |attrs| ::AuditEvents::AiAuditEvent.new(attrs) }

        ::AuditEvents::AiAuditEvents::WriteService.new(audit_events).execute
      end
    end
  end
end
