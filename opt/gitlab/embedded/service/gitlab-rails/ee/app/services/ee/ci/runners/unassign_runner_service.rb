# frozen_string_literal: true

module EE
  module Ci
    module Runners
      module UnassignRunnerService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          path = runner_path

          super.tap do |result|
            audit_event(path) if result.success?
          end
        end

        private

        AUDIT_MESSAGE = 'Unassigned CI runner from project'

        def audit_event(runner_path)
          ::Gitlab::Audit::Auditor.audit(
            name: 'ci_runner_unassigned_from_project',
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
