# frozen_string_literal: true

module Mutations
  module AuditEvents
    module InstanceExternalAuditEventDestinations
      class Destroy < Base
        graphql_name 'InstanceExternalAuditEventDestinationDestroy'

        authorize :admin_instance_external_audit_events

        authorize_granular_token permissions: :delete_audit_event_streaming_destination,
          boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        argument :id, ::Types::GlobalIDType[::AuditEvents::InstanceExternalAuditEventDestination],
          required: true,
          description: 'ID of the external instance audit event destination to destroy.'

        def resolve(id:)
          destination = find_object(id)
          paired_destination = destination.stream_destination

          if destination.destroy
            audit(destination, action: :destroy)

            paired_destination&.destroy
          end

          {
            instance_external_audit_event_destination: nil,
            errors: []
          }
        end
      end
    end
  end
end
