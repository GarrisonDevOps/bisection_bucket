# frozen_string_literal: true

module AuditEvents
  module AiAuditEvents
    # The settings that decide whether AI audit events are stored or streamed.
    # IngestAuditEventsService skips ProcessAuditEventsWorker when neither
    # applies, so the worker and the streamer must decide the same way.
    module Settings
      # Storage is off by default; only an explicit true opts in.
      def self.storage_enabled?(project_or_namespace)
        project_or_namespace&.ai_audit_events_storage_enabled == true
      end

      def self.streaming_enabled?(organization)
        return false unless organization

        !!::Ai::Setting.for_organization_read_only(organization).ai_audit_events_streaming_enabled
      end
    end
  end
end
