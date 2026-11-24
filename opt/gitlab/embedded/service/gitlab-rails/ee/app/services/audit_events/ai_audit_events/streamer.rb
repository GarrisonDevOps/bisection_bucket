# frozen_string_literal: true

module AuditEvents
  module AiAuditEvents
    class Streamer
      def self.stream(ai_audit_events)
        new(ai_audit_events).execute
      end

      def initialize(ai_audit_events)
        @ai_audit_events = ai_audit_events
        @streaming_enabled = {}
        @destinations = {}
      end

      def execute
        return if ::Gitlab::SilentMode.enabled?

        @ai_audit_events.each do |ai_audit_event|
          next unless stream?(ai_audit_event)

          ::AuditEvents::AiAuditEventStreamingWorker.perform_async(ai_audit_event.streaming_json)
        end
      end

      private

      # A batch resolves the setting and destinations once per scope instead of once per event.
      def stream?(ai_audit_event)
        scope = [ai_audit_event.project_id, ai_audit_event.namespace_id]
        enabled = @streaming_enabled.fetch(scope) do
          @streaming_enabled[scope] = instance_streaming_enabled?(ai_audit_event)
        end
        return false unless enabled

        @destinations.fetch(scope + [ai_audit_event.event_name]) do |key|
          @destinations[key] = destinations?(ai_audit_event)
        end
      end

      def instance_streaming_enabled?(ai_audit_event)
        ::AuditEvents::AiAuditEvents::Settings.streaming_enabled?(organization(ai_audit_event))
      end

      # The same check other audit events make before they enqueue a streaming job, in
      # AuditEvents::CommonAuditEventStreamable#can_stream_to_external_destination?
      def destinations?(ai_audit_event)
        ::AuditEvents::ExternalDestinationStreamer.new(ai_audit_event.event_name, ai_audit_event).streamable?
      end

      def organization(ai_audit_event)
        ::Project.find_by_id(ai_audit_event.project_id)&.organization ||
          ::Namespace.find_by_id(ai_audit_event.namespace_id)&.organization
      end
    end
  end
end
