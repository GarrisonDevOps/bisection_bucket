# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Streaming
      module InstanceHeaders
        class Update < Base
          graphql_name 'AuditEventsStreamingInstanceHeadersUpdate'

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          argument :header_id, ::Types::GlobalIDType[::AuditEvents::Streaming::InstanceHeader],
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

          field :header, ::Types::AuditEvents::Streaming::InstanceHeaderType,
            null: true,
            description: 'Updates header.'

          def resolve(header_id:, key:, value:, active:)
            header = find_header(header_id)

            response = ::AuditEvents::Streaming::InstanceHeaders::UpdateService.new(
              params: { header: header, key: key, value: value, active: active },
              current_user: current_user
            ).execute

            if response.success?
              { header: response.payload[:header], errors: [] }
            elsif header.present?
              { header: header.reset, errors: response.errors }
            end
          end
        end
      end
    end
  end
end
