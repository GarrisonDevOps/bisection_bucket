# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Streaming
      module InstanceHeaders
        class Destroy < Base
          graphql_name 'AuditEventsStreamingInstanceHeadersDestroy'

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          argument :header_id, ::Types::GlobalIDType[::AuditEvents::Streaming::InstanceHeader],
            required: true,
            description: 'Header to delete.'

          def resolve(header_id:)
            header = authorized_find!(id: header_id)

            response = ::AuditEvents::Streaming::InstanceHeaders::DestroyService.new(
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
