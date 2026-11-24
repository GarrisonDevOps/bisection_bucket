# frozen_string_literal: true

module AuditEvents
  module Streaming
    module Group
      class Streamer < BaseStreamer
        def streamable?
          group = audit_event.root_group_entity
          group.present? &&
            group.licensed_feature_available?(:external_audit_events) &&
            group.external_audit_event_streaming_destinations.active.allowed_for_event_type(event_type).exists?
        end

        def destinations
          group = audit_event.root_group_entity
          return [] unless group.present?

          group.external_audit_event_streaming_destinations.active.limit(5)
        end
      end
    end
  end
end
