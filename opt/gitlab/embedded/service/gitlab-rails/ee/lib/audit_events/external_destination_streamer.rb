# frozen_string_literal: true

module AuditEvents
  class ExternalDestinationStreamer
    attr_reader :event_name, :audit_event

    def initialize(event_name, audit_event)
      @event_name = event_name
      @audit_event = audit_event
    end

    def stream_to_destinations
      return unless streamers.any?(&:streamable?)

      streamers.each(&:execute)
    end

    def streamable?
      streamers.any?(&:streamable?)
    end

    private

    def streamers
      @streamers ||= [
        AuditEvents::Streaming::Group::Streamer.new(event_name, audit_event),
        AuditEvents::Streaming::Instance::Streamer.new(event_name, audit_event)
      ]
    end
  end
end
