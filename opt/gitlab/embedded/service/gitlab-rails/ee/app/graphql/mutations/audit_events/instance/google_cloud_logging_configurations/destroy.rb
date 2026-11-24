# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module GoogleCloudLoggingConfigurations
        class Destroy < Base
          graphql_name 'InstanceGoogleCloudLoggingConfigurationDestroy'

          authorize_granular_token permissions: :delete_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          argument :id, ::Types::GlobalIDType[::AuditEvents::Instance::GoogleCloudLoggingConfiguration],
            required: true,
            description: 'ID of the Google Cloud logging configuration to destroy.'

          def resolve(id:)
            config = authorized_find!(id)
            paired_destination = config.stream_destination

            if config.destroy
              audit(config, action: :deleted)

              paired_destination&.destroy
            end

            { errors: Array(config.errors) }
          end
        end
      end
    end
  end
end
