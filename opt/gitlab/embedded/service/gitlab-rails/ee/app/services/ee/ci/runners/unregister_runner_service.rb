# frozen_string_literal: true

module EE
  module Ci
    module Runners
      # Unregisters a CI Runner and logs an audit event
      #
      module UnregisterRunnerService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          scopes = runner_scopes # Save the scopes before destroying the record

          super.tap do |result|
            audit_event(scopes) if result.success?
          end
        end

        private

        def runner_scopes
          case runner.runner_type
          when 'group_type'
            runner.groups.to_a
          when 'project_type'
            runner.projects.to_a
          else
            [::Gitlab::Audit::InstanceScope.new]
          end
        end

        def audit_event(scopes)
          scopes.each do |scope|
            ::AuditEvents::RunnerAuditEventService.new(
              runner, author, scope,
              name: 'ci_runner_unregistered', message: audit_message, runner_contacted_at: runner.contacted_at
            ).track_event
          end
        end

        def audit_message
          return 'Unregistered %{runner_type} CI runner, never contacted' if runner.contacted_at.nil?

          'Unregistered %{runner_type} CI runner, last contacted %{runner_contacted_at}'
        end
      end
    end
  end
end
