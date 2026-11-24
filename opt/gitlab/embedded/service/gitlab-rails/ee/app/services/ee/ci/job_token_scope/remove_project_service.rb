# frozen_string_literal: true

module EE
  module Ci
    module JobTokenScope
      module RemoveProjectService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute(target_project, direction)
          super.tap do |response|
            if direction == :inbound && response.success?
              audit(project, target_project, current_user, response.payload.job_token_policies)
            end
          end
        end

        private

        def audit(scope, target, author, policies)
          audit_message =
            "Project #{target.full_path} was removed from inbound list of allowed projects for #{scope.full_path}"
          audit_message += ", with job token policies: #{policies.join(', ')}" if policies.present?
          event_name = 'secure_ci_job_token_project_removed'

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
