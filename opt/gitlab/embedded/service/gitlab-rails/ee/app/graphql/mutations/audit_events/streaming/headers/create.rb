# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Streaming
      module Headers
        class Create < BaseMutation
          graphql_name 'AuditEventsStreamingHeadersCreate'
          authorize :admin_external_audit_events

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary_argument: :destination_id, boundary: :group, boundary_type: :group

          argument :key, GraphQL::Types::String,
            required: true,
            description: 'Header key.'

          argument :value, GraphQL::Types::String,
            required: true,
            description: 'Header value.'

          argument :destination_id, ::Types::GlobalIDType[::AuditEvents::ExternalAuditEventDestination],
            required: true,
            description: 'Destination to associate header with.'

          argument :active, GraphQL::Types::Boolean,
            required: false,
            default_value: true,
            description: 'Boolean option determining whether header is active or not.'

          field :header, ::Types::AuditEvents::Streaming::HeaderType,
            null: true,
            description: 'Created header.'

          def resolve(destination_id:, key:, value:, active:)
            response = ::AuditEvents::Streaming::Headers::CreateService.new(
              destination: authorized_find!(id: destination_id),
              params: { key: key, value: value, active: active },
              current_user: current_user
            ).execute

            if response.success?
              { header: response.payload[:header], errors: [] }
            else
              { header: nil, errors: response.errors }
            end
          end
        end
      end
    end
  end
end
