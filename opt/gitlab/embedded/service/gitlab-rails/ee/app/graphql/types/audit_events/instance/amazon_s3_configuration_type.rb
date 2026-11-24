# frozen_string_literal: true

module Types
  module AuditEvents
    module Instance
      class AmazonS3ConfigurationType < ::Types::BaseObject
        graphql_name 'InstanceAmazonS3ConfigurationType'
        description 'Stores instance level Amazon S3 configurations for audit event streaming.'
        authorize :admin_instance_external_audit_events

        implements AmazonS3ConfigurationInterface
      end
    end
  end
end
