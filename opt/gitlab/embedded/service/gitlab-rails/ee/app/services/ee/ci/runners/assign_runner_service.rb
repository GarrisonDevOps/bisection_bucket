# frozen_string_literal: true

module EE
  module Ci
    module Runners
      module AssignRunnerService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          super.tap do |result|
            audit_event if result.success?
          end
        end

        private

        AUDIT_MESSAGE = 'Assigned CI runner to project'

        def audit_event
          return if quiet

          ::Gitlab::Audit::Auditor.audit(
            name: 'ci_runner_assigned_to_project',
            author: user,
            scope: project,
            target: runner,
            target_details: runner_path,
            message: AUDIT_MESSAGE)
        end

        def runner_path
          url_helpers = ::Gitlab::Routing.url_helpers

          runner.owner ? url_helpers.project_runner_path(runner.owner, runner) : nil
        end
      end
    end
  end
end
