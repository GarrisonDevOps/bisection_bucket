# frozen_string_literal: true

module Mutations
  module AuditEvents
    module GoogleCloudLoggingConfigurations
      class Destroy < Base
        graphql_name 'GoogleCloudLoggingConfigurationDestroy'

        authorize :admin_external_audit_events

        authorize_granular_token permissions: :delete_audit_event_streaming_destination,
          boundary_argument: :id, boundary: :group, boundary_type: :group

        argument :id, ::Types::GlobalIDType[::AuditEvents::GoogleCloudLoggingConfiguration],
          required: true,
          description: 'ID of the Google Cloud logging configuration to destroy.'

        def resolve(id:)
          config = authorized_find!(id)
          paired_destination = config.stream_destination

          if config.destroy
            audit(config, action: :deleted)

            paired_destination&.destroy

            { errors: [] }
          else
            { errors: Array(config.errors) }
          end
        end

        private

        def find_object(config_gid)
          GitlabSchema.object_from_id(
            config_gid,
            expected_type: ::AuditEvents::GoogleCloudLoggingConfiguration).sync
        end
      end
    end
  end
end
