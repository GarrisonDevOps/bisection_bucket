# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Streaming
      module Headers
        class Update < BaseMutation
          graphql_name 'AuditEventsStreamingHeadersUpdate'
          authorize :admin_external_audit_events

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary_argument: :header_id, boundary: :group, boundary_type: :group

          argument :header_id, ::Types::GlobalIDType[::AuditEvents::Streaming::Header],
            required: true,
            description: 'Header to update.'

          argument :key, GraphQL::Types::String,
            required: false,
            default_value: nil,
            description: 'Header key.'

          argument :value, GraphQL::Types::String,
            required: false,
            default_value: nil,
            description: 'Header value.'

          argument :active, GraphQL::Types::Boolean,
            required: false,
            default_value: nil,
            description: 'Boolean option determining whether header is active or not.'

          field :header, ::Types::AuditEvents::Streaming::HeaderType,
            null: true,
            description: 'Updates header.'

          def resolve(header_id:, key:, value:, active:)
            header = authorized_find!(id: header_id)

            response = ::AuditEvents::Streaming::Headers::UpdateService.new(
              destination: header.external_audit_event_destination,
              params: { header: header, key: key, value: value, active: active },
              current_user: current_user
            ).execute

            if response.success?
              { header: response.payload[:header], errors: [] }
            else
              { header: header.reset, errors: response.errors }
            end
          end
        end
      end
    end
  end
end
