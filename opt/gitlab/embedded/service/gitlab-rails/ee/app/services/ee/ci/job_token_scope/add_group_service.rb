# frozen_string_literal: true

module EE
  module Ci
    module JobTokenScope
      module AddGroupService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute(target_group, default_permissions: true, policies: [])
          super.tap do |response|
            audit(project, target_group, current_user, default_permissions, policies) if response.success?
          end
        end

        private

        def audit(scope, target, author, default_permissions, policies)
          audit_message =
            "Group #{target.full_path} was added to list of allowed groups for #{scope.full_path}"
          event_name = 'secure_ci_job_token_group_added'

          if policies.present?
            audit_message += ", with default permissions: #{default_permissions}, " \
              "job token policies: #{policies.join(', ')}"
          end

          audit_context = {
            name: event_name,
            author: author,
            scope: scope,
            target: target,
            message: audit_message
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
