# frozen_string_literal: true

module EE
  module Ci
    module Runners
      module SetRunnerAssociatedProjectsService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          super.tap { |result| audit_event_service(result) }
        end

        private

        def audit_event_service(result)
          return if result.error?

          ::Gitlab::Audit::Auditor.audit(
            name: 'set_runner_associated_projects',
            author: current_user,
            scope: runner.owner,
            target: runner,
            target_details: runner_path,
            message: 'Changed CI runner project assignments',
            additional_details: {
              action: :custom,
              added_project_ids: result.payload[:added_to_projects].map(&:id),
              deleted_from_projects: result.payload[:deleted_from_projects].map(&:id)
            })

          audit_project_events(
            result.payload[:added_to_projects], EE::Ci::Runners::AssignRunnerService::AUDIT_MESSAGE)
          audit_project_events(
            result.payload[:deleted_from_projects], EE::Ci::Runners::UnassignRunnerService::AUDIT_MESSAGE)
        end

        def runner_path
          url_helpers = ::Gitlab::Routing.url_helpers

          runner.owner ? url_helpers.project_runner_path(runner.owner, runner) : nil
        end

        def audit_project_events(projects, audit_message)
          projects.each do |project|
            ::Gitlab::Audit::Auditor.audit(
              name: 'set_runner_associated_projects',
              author: current_user,
              scope: project,
              target: runner,
              target_details: runner_path,
              message: audit_message)
          end
        end
      end
    end
  end
end
