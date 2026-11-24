# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Group
      module EventTypeFilters
        class DenylistDelete < BaseMutation
          graphql_name 'AuditEventsGroupDestinationDenylistEventsDelete'
          authorize :admin_external_audit_events

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary_argument: :destination_id, boundary: :group, boundary_type: :group

          argument :destination_id, ::Types::GlobalIDType[::AuditEvents::Group::ExternalStreamingDestination],
            required: true,
            description: 'Destination id.'

          argument :event_type_filters, [GraphQL::Types::String],
            required: true,
            description: 'List of event type filters to remove from the denylist.',
            prepare: ->(filters, _ctx) do
              filters.presence || (raise ::Gitlab::Graphql::Errors::ArgumentError,
                'event type filters must be present')
            end

          def resolve(destination_id:, event_type_filters:)
            destination = authorized_find!(id: destination_id)

            response = ::AuditEvents::Group::EventTypeFilters::Denylist::DestroyService.new(
              destination: destination,
              event_type_filters: event_type_filters,
              current_user: current_user
            ).execute

            { errors: response.success? ? [] : response.errors }
          end
        end
      end
    end
  end
end
