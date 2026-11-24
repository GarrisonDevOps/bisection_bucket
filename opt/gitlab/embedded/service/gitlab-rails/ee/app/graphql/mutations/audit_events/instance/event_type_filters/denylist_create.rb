# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module EventTypeFilters
        class DenylistCreate < BaseMutation
          graphql_name 'AuditEventsInstanceDestinationDenylistEventsAdd'
          authorize :update_audit_event_streaming_destination

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          argument :destination_id, ::Types::GlobalIDType[::AuditEvents::Instance::ExternalStreamingDestination],
            required: true,
            description: 'Destination id.'

          argument :event_type_filters, [GraphQL::Types::String],
            required: true,
            validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
            description: "List of event type filters to add to the denylist " \
              "(maximum is #{::Types::BaseArgument::MAX_ARRAY_SIZE}).",
            prepare: ->(filters, _ctx) do
              filters.presence || (raise ::Gitlab::Graphql::Errors::ArgumentError,
                'event type filters must be present')
            end

          field :event_type_filters, [GraphQL::Types::String],
            null: true,
            description: 'List of denylisted event type filters for the audit event external destination.'

          def resolve(destination_id:, event_type_filters:)
            destination = authorized_find!(id: destination_id)

            response = ::AuditEvents::Instance::EventTypeFilters::Denylist::CreateService.new(
              destination: destination,
              event_type_filters: event_type_filters,
              current_user: current_user
            ).execute

            {
              event_type_filters: destination.event_type_denylist_filters.pluck_audit_event_type,
              errors: response.errors
            }
          end
        end
      end
    end
  end
end
