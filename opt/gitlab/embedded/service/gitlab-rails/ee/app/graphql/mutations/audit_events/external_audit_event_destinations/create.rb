# frozen_string_literal: true

module Mutations
  module AuditEvents
    module ExternalAuditEventDestinations
      class Create < Base
        graphql_name 'ExternalAuditEventDestinationCreate'

        include ::AuditEvents::LegacyDestinationSyncHelper
        include ::Mutations::AuditEvents::DestinationRateLimitable

        authorize :admin_external_audit_events

        authorize_granular_token permissions: :create_audit_event_streaming_destination,
          boundary_argument: :group_path, boundary_type: :group

        argument :destination_url, GraphQL::Types::String,
          required: true,
          description: 'Destination URL.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Destination name.'

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group path.'

        argument :verification_token, GraphQL::Types::String,
          required: false,
          description: 'Verification token.'

        field :external_audit_event_destination, ::Types::AuditEvents::ExternalAuditEventDestinationType,
          null: true,
          description: 'Destination created.'

        def resolve(destination_url:, group_path:, verification_token: nil, name: nil)
          group = authorized_find!(group_path)
          return destination_rate_limited_response if destination_rate_limited?(group)

          destination = ::AuditEvents::ExternalAuditEventDestination.new(group: group,
            destination_url: destination_url,
            verification_token: verification_token,
            name: name)

          destination.save!
          audit(destination, action: :create)
          create_stream_destination(legacy_destination_model: destination, category: :http, is_instance: false)
          { external_audit_event_destination: destination, errors: [] }

        rescue ActiveRecord::RecordInvalid => e
          raise Gitlab::Graphql::Errors::ArgumentError, e.message
        end

        private

        def find_object(group_path)
          ::Group.find_by_full_path(group_path)
        end
      end
    end
  end
end
