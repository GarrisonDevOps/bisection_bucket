# frozen_string_literal: true

module Mutations
  module AuditEvents
    module InstanceExternalAuditEventDestinations
      class Update < Base
        graphql_name 'InstanceExternalAuditEventDestinationUpdate'

        include ::AuditEvents::Changes
        include ::AuditEvents::LegacyDestinationSyncHelper

        authorize :admin_instance_external_audit_events

        authorize_granular_token permissions: :update_audit_event_streaming_destination,
          boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        UPDATE_EVENT_NAME = 'update_instance_event_streaming_destination'
        AUDIT_EVENT_COLUMNS = [:destination_url, :name, :active].freeze

        argument :id, ::Types::GlobalIDType[::AuditEvents::InstanceExternalAuditEventDestination],
          required: true,
          description: 'ID of the external instance audit event destination to update.'

        argument :destination_url, GraphQL::Types::String,
          required: false,
          description: 'Destination URL to change.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Destination name.'

        argument :active, GraphQL::Types::Boolean,
          required: false,
          description: 'Active status of the destination.'

        field :instance_external_audit_event_destination,
          ::Types::AuditEvents::InstanceExternalAuditEventDestinationType,
          null: true,
          description: 'Updated destination.'

        def resolve(id:, destination_url: nil, name: nil, active: nil)
          destination = find_object(id)

          destination_attributes = { destination_url: destination_url, name: name, active: active }.compact

          if destination.update(destination_attributes)
            audit_update(destination)
            update_stream_destination(legacy_destination_model: destination)
          end

          {
            instance_external_audit_event_destination: (destination if destination.persisted?),
            errors: Array(destination.errors)
          }
        end

        private

        def audit_update(destination)
          AUDIT_EVENT_COLUMNS.each do |column|
            next unless destination.saved_change_to_attribute?(column)

            audit_changes(
              column,
              as: column.to_s,
              entity: Gitlab::Audit::InstanceScope.new,
              model: destination,
              event_type: UPDATE_EVENT_NAME
            )
          end
        end
      end
    end
  end
end
