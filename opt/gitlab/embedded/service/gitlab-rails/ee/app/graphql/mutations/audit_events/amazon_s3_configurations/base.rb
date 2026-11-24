# frozen_string_literal: true

module Mutations
  module AuditEvents
    module AmazonS3Configurations
      class Base < BaseMutation
        authorize :admin_external_audit_events

        private

        def audit(config, action:)
          audit_context = {
            name: "amazon_s3_configuration_#{action}",
            author: current_user,
            scope: config.group,
            target: config.group,
            message: "#{action.capitalize} Amazon S3 configuration with name: #{config.name} bucket: " \
                     "#{config.bucket_name} and AWS region: #{config.aws_region}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
