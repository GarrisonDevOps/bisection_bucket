# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module AmazonS3Configurations
        class Create < Base
          graphql_name 'AuditEventsInstanceAmazonS3ConfigurationCreate'

          authorize_granular_token permissions: :create_audit_event_streaming_destination,
            boundary: :instance, boundary_type: :instance,
            assignable_when: [:admin]

          include ::AuditEvents::LegacyDestinationSyncHelper

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Destination name.'

          argument :access_key_xid, GraphQL::Types::String,
            required: true,
            description: 'Access key ID of the Amazon S3 account.'

          argument :secret_access_key, GraphQL::Types::String,
            required: true,
            description: 'Secret access key of the Amazon S3 account.'

          argument :bucket_name, GraphQL::Types::String,
            required: true,
            description: 'Name of the bucket where the audit events would be logged.'

          argument :aws_region, GraphQL::Types::String,
            required: true,
            description: 'AWS region where the bucket is created.'

          field :instance_amazon_s3_configuration, ::Types::AuditEvents::Instance::AmazonS3ConfigurationType,
            null: true,
            description: 'Created instance Amazon S3 configuration.'

          def resolve(access_key_xid:, secret_access_key:, bucket_name:, aws_region:, name: nil)
            config_attributes = {
              access_key_xid: access_key_xid,
              secret_access_key: secret_access_key,
              bucket_name: bucket_name,
              aws_region: aws_region,
              name: name
            }

            config = ::AuditEvents::Instance::AmazonS3Configuration.new(config_attributes)

            if config.save
              audit(config, action: :created)

              create_stream_destination(legacy_destination_model: config, category: :aws, is_instance: true)

              { instance_amazon_s3_configuration: config, errors: [] }
            else
              { instance_amazon_s3_configuration: nil, errors: Array(config.errors) }
            end
          end
        end
      end
    end
  end
end
