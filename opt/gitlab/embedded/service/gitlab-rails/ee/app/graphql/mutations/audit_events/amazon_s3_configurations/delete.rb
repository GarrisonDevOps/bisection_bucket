# frozen_string_literal: true

module Mutations
  module AuditEvents
    module AmazonS3Configurations
      class Delete < Base
        graphql_name 'AuditEventsAmazonS3ConfigurationDelete'

        authorize_granular_token permissions: :delete_audit_event_streaming_destination,
          boundary_argument: :id, boundary: :group, boundary_type: :group

        argument :id, ::Types::GlobalIDType[::AuditEvents::AmazonS3Configuration],
          required: true,
          description: 'ID of the Amazon S3 configuration to destroy.'

        def resolve(id:)
          config = authorized_find!(id: id)
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
