# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module EventTypeFilters
        class Create < Streaming::BaseEventTypeFilters::BaseCreate
          graphql_name 'AuditEventsInstanceDestinationEventsAdd'
          authorize :admin_instance_external_audit_events

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          argument :destination_id, ::Types::GlobalIDType[::AuditEvents::Instance::ExternalStreamingDestination],
            required: true,
            description: 'Destination id.'
        end
      end
    end
  end
end
