# frozen_string_literal: true

module Mutations
  module AuditEvents
    module ExternalAuditEventDestinations
      class Update < Base
        graphql_name 'ExternalAuditEventDestinationUpdate'

        include ::AuditEvents::Changes
        include ::AuditEvents::LegacyDestinationSyncHelper
        include ::Mutations::AuditEvents::DestinationRateLimitable

        UPDATE_EVENT_NAME = 'update_event_streaming_destination'
        AUDIT_EVENT_COLUMNS = [:destination_url, :name, :active].freeze

        authorize :admin_external_audit_events

        authorize_granular_token permissions: :update_audit_event_streaming_destination,
          boundary_argument: :id, boundary: :group, boundary_type: :group

        argument :id, ::Types::GlobalIDType[::AuditEvents::ExternalAuditEventDestination],
          required: true,
          description: 'ID of external audit event destination to update.'

        argument :destination_url, GraphQL::Types::String,
          required: false,
          description: 'Destination URL to change.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Destination name.'

        argument :active, GraphQL::Types::Boolean,
          required: false,
          description: 'Active status of the destination.'

        field :external_audit_event_destination, ::Types::AuditEvents::ExternalAuditEventDestinationType,
          null: true,
          description: 'Updated destination.'

        def resolve(id:, destination_url: nil, name: nil, active: nil)
          destination = authorized_find!(id)
          return destination_rate_limited_response if destination_rate_limited?(destination.group)

          destination_attributes = {
            destination_url: destination_url,
            name: name,
            active: active
          }.compact

          if destination.update(destination_attributes)
            audit_update(destination)
            update_stream_destination(legacy_destination_model: destination)
          end

          {
            external_audit_event_destination: (destination if destination.persisted?),
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
              entity: destination.group,
              model: destination,
              event_type: UPDATE_EVENT_NAME
            )
          end
        end

        def find_object(destination_gid)
          GitlabSchema.object_from_id(destination_gid, expected_type: ::AuditEvents::ExternalAuditEventDestination).sync
        end
      end
    end
  end
end
