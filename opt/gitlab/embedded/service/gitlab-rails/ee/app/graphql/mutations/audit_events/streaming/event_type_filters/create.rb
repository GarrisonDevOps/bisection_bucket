# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Streaming
      module EventTypeFilters
        class Create < BaseEventTypeFilters::BaseCreate
          graphql_name 'AuditEventsStreamingDestinationEventsAdd'
          authorize :admin_external_audit_events

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary_argument: :destination_id, boundary: :group, boundary_type: :group

          argument :destination_id, ::Types::GlobalIDType[::AuditEvents::ExternalAuditEventDestination],
            required: true,
            description: 'Destination id.'
        end
      end
    end
  end
end
