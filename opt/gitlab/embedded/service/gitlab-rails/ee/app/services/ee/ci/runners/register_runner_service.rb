# frozen_string_literal: true

module EE
  module Ci
    module Runners
      module RegisterRunnerService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          super.tap do |result|
            audit_event(result.payload[:runner]) if result.success?
          end
        end

        private

        def audit_event(runner)
          return unless runner.valid?

          ::AuditEvents::RunnerAuditEventService.new(
            runner, registration_token, token_scope,
            name: 'ci_runner_registered', message: 'Registered %{runner_type} CI runner',
            token_field: :runner_registration_token
          ).track_event
        end
      end
    end
  end
end
