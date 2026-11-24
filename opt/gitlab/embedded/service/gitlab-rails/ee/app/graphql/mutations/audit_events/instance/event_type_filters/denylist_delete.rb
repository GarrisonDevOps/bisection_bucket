# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module EventTypeFilters
        class DenylistDelete < BaseMutation
          graphql_name 'AuditEventsInstanceDestinationDenylistEventsDelete'
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
            description: "List of event type filters to remove from the denylist " \
              "(maximum is #{::Types::BaseArgument::MAX_ARRAY_SIZE}).",
            prepare: ->(filters, _ctx) do
              filters.presence || (raise ::Gitlab::Graphql::Errors::ArgumentError,
                'event type filters must be present')
            end

          def resolve(destination_id:, event_type_filters:)
            destination = authorized_find!(id: destination_id)

            response = ::AuditEvents::Instance::EventTypeFilters::Denylist::DestroyService.new(
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
