# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module GoogleCloudLoggingConfigurations
        class Update < Base
          graphql_name 'InstanceGoogleCloudLoggingConfigurationUpdate'

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          include Mutations::AuditEvents::GoogleCloudLoggingConfigurations::CommonUpdate

          UPDATE_EVENT_NAME = 'instance_google_cloud_logging_configuration_updated'

          argument :id, ::Types::GlobalIDType[::AuditEvents::Instance::GoogleCloudLoggingConfiguration],
            required: true,
            description: 'ID of the instance google Cloud configuration to update.'

          field :instance_google_cloud_logging_configuration,
            ::Types::AuditEvents::Instance::GoogleCloudLoggingConfigurationType,
            null: true,
            description: 'configuration updated.'

          def resolve(
            id:, google_project_id_name: nil, client_email: nil, private_key: nil, log_id_name: nil, name: nil,
            active: nil)
            config, errors = update_config(id: id, google_project_id_name: google_project_id_name,
              client_email: client_email, private_key: private_key,
              log_id_name: log_id_name, name: name, active: active)

            { instance_google_cloud_logging_configuration: config, errors: errors }
          end
        end
      end
    end
  end
end
