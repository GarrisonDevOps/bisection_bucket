# frozen_string_literal: true

module Types
  module AuditEvents
    module AmazonS3ConfigurationInterface
      include Types::BaseInterface

      field :id, GraphQL::Types::ID,
        null: false,
        description: 'ID of the configuration.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the external destination to send audit events to.'

      field :access_key_xid, GraphQL::Types::String,
        null: false,
        description: 'Access key ID of the Amazon S3 account.'

      field :bucket_name, GraphQL::Types::String,
        null: false,
        description: 'Name of the bucket where the audit events would be logged.'

      field :aws_region, GraphQL::Types::String,
        null: false,
        description: 'AWS region where the bucket is created.'

      field :active, GraphQL::Types::Boolean,
        null: false,
        description: 'Active status of the destination.'
    end
  end
end
