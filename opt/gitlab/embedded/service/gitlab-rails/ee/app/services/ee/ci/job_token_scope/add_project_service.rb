# frozen_string_literal: true

module EE
  module Ci
    module JobTokenScope
      module AddProjectService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute(target_project, default_permissions: true, policies: [], direction: :inbound)
          super.tap do |response|
            if direction == :inbound && response.success?
              audit(project, target_project, current_user, default_permissions,
                policies)
            end
          end
        end

        private

        def audit(scope, target, author, default_permissions, policies)
          audit_message =
            "Project #{target.full_path} was added to inbound list of allowed projects for #{scope.full_path}"
          event_name = 'secure_ci_job_token_project_added'

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
