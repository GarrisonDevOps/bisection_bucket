# frozen_string_literal: true

module Mutations
  module AuditEvents
    module InstanceExternalAuditEventDestinations
      class Create < Base
        graphql_name 'InstanceExternalAuditEventDestinationCreate'

        include ::AuditEvents::LegacyDestinationSyncHelper

        authorize :admin_instance_external_audit_events

        authorize_granular_token permissions: :create_audit_event_streaming_destination,
          boundary: :instance, boundary_type: :instance,
          assignable_when: [:admin]

        argument :destination_url, GraphQL::Types::String,
          required: true,
          description: 'Destination URL.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Destination name.'

        field :instance_external_audit_event_destination,
          ::Types::AuditEvents::InstanceExternalAuditEventDestinationType,
          null: true,
          description: 'Destination created.'

        def resolve(destination_url:, name: nil)
          destination = ::AuditEvents::InstanceExternalAuditEventDestination.new(destination_url: destination_url,
            name: name)

          destination.save!
          create_stream_destination(legacy_destination_model: destination, category: :http, is_instance: true)
          audit(destination, action: :create)

          {
            instance_external_audit_event_destination: destination,
            errors: []
          }

        rescue ActiveRecord::RecordInvalid => e
          raise Gitlab::Graphql::Errors::ArgumentError, e.message
        end
      end
    end
  end
end
