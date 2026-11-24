# frozen_string_literal: true

module Mutations
  module AuditEvents
    module AmazonS3Configurations
      class Create < Base
        graphql_name 'AuditEventsAmazonS3ConfigurationCreate'

        authorize_granular_token permissions: :create_audit_event_streaming_destination,
          boundary_argument: :group_path, boundary_type: :group

        include ::AuditEvents::LegacyDestinationSyncHelper
        include ::Mutations::AuditEvents::DestinationRateLimitable

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Destination name.'

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group path.'

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

        field :amazon_s3_configuration, ::Types::AuditEvents::AmazonS3ConfigurationType,
          null: true,
          description: 'configuration created.'

        def resolve(group_path:, access_key_xid:, secret_access_key:, bucket_name:, aws_region:, name: nil)
          group = authorized_find!(group_path)
          return destination_rate_limited_response if destination_rate_limited?(group)

          config_attributes = {
            group: group,
            access_key_xid: access_key_xid,
            secret_access_key: secret_access_key,
            bucket_name: bucket_name,
            aws_region: aws_region,
            name: name
          }

          config = ::AuditEvents::AmazonS3Configuration.new(config_attributes)

          if config.save
            audit(config, action: :created)

            create_stream_destination(legacy_destination_model: config, category: :aws, is_instance: false)

            { amazon_s3_configuration: config, errors: [] }
          else
            { amazon_s3_configuration: nil, errors: Array(config.errors) }
          end
        end

        private

        def find_object(group_path)
          ::Group.find_by_full_path(group_path)
        end
      end
    end
  end
end
