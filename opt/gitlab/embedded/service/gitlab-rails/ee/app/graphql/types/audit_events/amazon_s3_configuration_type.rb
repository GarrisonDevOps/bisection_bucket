# frozen_string_literal: true

module Types
  module AuditEvents
    class AmazonS3ConfigurationType < ::Types::BaseObject
      graphql_name 'AmazonS3ConfigurationType'
      description 'Stores Amazon S3 configurations for audit event streaming.'
      authorize :admin_external_audit_events

      implements AmazonS3ConfigurationInterface

      field :group, ::Types::GroupType,
        null: false,
        description: 'Group the configuration belongs to.'
    end
  end
end
