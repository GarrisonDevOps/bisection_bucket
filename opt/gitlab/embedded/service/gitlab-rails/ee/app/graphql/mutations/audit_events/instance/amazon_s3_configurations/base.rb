# frozen_string_literal: true

module Mutations
  module AuditEvents
    module Instance
      module AmazonS3Configurations
        class Base < BaseMutation
          authorize :admin_instance_external_audit_events

          def ready?(**args)
            unless Ability.allowed?(current_user, :admin_instance_external_audit_events)
              raise_resource_not_available_error!
            end

            super
          end

          private

          def audit(config, action:)
            audit_context = {
              name: "instance_amazon_s3_configuration_#{action}",
              author: current_user,
              scope: Gitlab::Audit::InstanceScope.new,
              target: config,
              message: "#{action.capitalize} Instance Amazon S3 configuration with name: #{config.name} " \
                       "bucket: #{config.bucket_name} and AWS region: #{config.aws_region}"
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end
        end
      end
    end
  end
end
