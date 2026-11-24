# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Streaming
      module Headers
        class Destroy < BaseMutation
          graphql_name 'AuditEventsStreamingHeadersDestroy'
          authorize :admin_external_audit_events

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary_argument: :header_id, boundary: :group, boundary_type: :group

          argument :header_id, ::Types::GlobalIDType[::AuditEvents::Streaming::Header],
            required: true,
            description: 'Header to delete.'

          def resolve(header_id:)
            header = authorized_find!(id: header_id)

            response = ::AuditEvents::Streaming::Headers::DestroyService.new(
              destination: header.external_audit_event_destination,
              params: { header: header },
              current_user: current_user
            ).execute

            if response.success?
              { header: nil, errors: [] }
            else
              { header: header, errors: response.errors }
            end
          end
        end
      end
    end
  end
end
