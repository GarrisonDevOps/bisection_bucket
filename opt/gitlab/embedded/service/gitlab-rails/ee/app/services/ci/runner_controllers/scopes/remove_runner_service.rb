# frozen_string_literal: true

module Ci
  module RunnerControllers
    module Scopes
      class RemoveRunnerService
        attr_reader :runner_controller, :runner, :current_user

        def initialize(runner_controller:, runner:, current_user:)
          @runner_controller = runner_controller
          @runner = runner
          @current_user = current_user
        end

        def execute
          return error_no_permissions unless current_user.can_admin_all_resources?

          scoping = runner_controller.runner_level_scopings.for_runner(runner.id).first
          return ServiceResponse.success if scoping.nil?

          if scoping.destroy
            audit_event(scoping)
            ServiceResponse.success
          else
            ServiceResponse.error(message: scoping.errors.full_messages.to_sentence, reason: :bad_request)
          end
        end

        private

        def audit_event(scoping)
          ::AuditEvents::RunnerControllerAuditEventService.new(
            scoping, current_user,
            name: 'runner_controller_runner_scope_removed',
            message: "Removed runner scope for runner ##{runner.id} from runner controller"
          ).track_event
        end

        def error_no_permissions
          ServiceResponse.error(
            message: 'Administrator permission is required to remove runner scope',
            reason: :forbidden
          )
        end
      end
    end
  end
end
