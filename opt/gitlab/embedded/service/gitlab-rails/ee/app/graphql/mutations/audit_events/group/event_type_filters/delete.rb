# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Group
      module EventTypeFilters
        class Delete < Streaming::BaseEventTypeFilters::BaseDestroy
          graphql_name 'AuditEventsGroupDestinationEventsDelete'
          authorize :admin_external_audit_events

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary_argument: :destination_id, boundary: :group, boundary_type: :group

          argument :destination_id, ::Types::GlobalIDType[::AuditEvents::Group::ExternalStreamingDestination],
            required: true,
            description: 'Destination id.'
        end
      end
    end
  end
end
