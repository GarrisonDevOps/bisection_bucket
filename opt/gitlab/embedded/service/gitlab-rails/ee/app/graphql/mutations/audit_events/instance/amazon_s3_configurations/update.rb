# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module AmazonS3Configurations
        class Update < Base
          graphql_name 'AuditEventsInstanceAmazonS3ConfigurationUpdate'

          authorize_granular_token permissions: :update_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          include ::AuditEvents::Changes
          include ::AuditEvents::LegacyDestinationSyncHelper

          UPDATE_EVENT_NAME = 'instance_amazon_s3_configuration_updated'
          AUDIT_EVENT_COLUMNS = [:access_key_xid, :secret_access_key, :bucket_name, :aws_region, :name, :active].freeze

          argument :id, ::Types::GlobalIDType[::AuditEvents::Instance::AmazonS3Configuration],
            required: true,
            description: 'ID of the instance-level Amazon S3 configuration to update.'

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Destination name.'

          argument :access_key_xid, GraphQL::Types::String,
            required: false,
            description: 'Access key ID of the Amazon S3 account.'

          argument :secret_access_key, GraphQL::Types::String,
            required: false,
            description: 'Secret access key of the Amazon S3 account.'

          argument :bucket_name, GraphQL::Types::String,
            required: false,
            description: 'Name of the bucket where the audit events would be logged.'

          argument :aws_region, GraphQL::Types::String,
            required: false,
            description: 'AWS region where the bucket is created.'

          argument :active, GraphQL::Types::Boolean,
            required: false,
            description: 'Active status of the destination.'

          field :instance_amazon_s3_configuration, ::Types::AuditEvents::Instance::AmazonS3ConfigurationType,
            null: true,
            description: 'Updated instance-level Amazon S3 configuration.'

          def resolve(
            id:, access_key_xid: nil, secret_access_key: nil, bucket_name: nil, aws_region: nil, name: nil, active: nil
          )
            config = authorized_find!(id: id)

            config_attributes = {
              access_key_xid: access_key_xid,
              secret_access_key: secret_access_key,
              bucket_name: bucket_name,
              aws_region: aws_region,
              name: name,
              active: active
            }.compact

            if config.update(config_attributes)
              audit_update(config)
              update_stream_destination(legacy_destination_model: config)
              { instance_amazon_s3_configuration: config, errors: [] }
            else
              { instance_amazon_s3_configuration: nil, errors: Array(config.errors) }
            end
          end

          private

          def audit_update(config)
            AUDIT_EVENT_COLUMNS.each do |column|
              audit_changes(
                column,
                as: column.to_s,
                entity: Gitlab::Audit::InstanceScope.new,
                model: config,
                event_type: UPDATE_EVENT_NAME
              )
            end
          end
        end
      end
    end
  end
end
