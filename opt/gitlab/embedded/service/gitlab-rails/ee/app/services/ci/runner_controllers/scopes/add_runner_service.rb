# frozen_string_literal: true

module Ci
  module RunnerControllers
    module Scopes
      class AddRunnerService
        attr_reader :runner_controller, :runner, :current_user

        def initialize(runner_controller:, runner:, current_user:)
          @runner_controller = runner_controller
          @runner = runner
          @current_user = current_user
        end

        def execute
          return error_no_permissions unless current_user.can_admin_all_resources?
          return error_runner_not_instance_type unless runner.instance_type?
          return error_has_instance_scoping if runner_controller.instance_level_scoping.present?
          return error_already_exists if scoping_exists?

          scoping = runner_controller.runner_level_scopings.build(runner: runner)

          if scoping.save
            audit_event(scoping)
            ServiceResponse.success(payload: scoping)
          else
            ServiceResponse.error(message: scoping.errors.full_messages.to_sentence, reason: :bad_request)
          end
        rescue ActiveRecord::RecordNotUnique
          error_already_exists
        end

        private

        def audit_event(scoping)
          ::AuditEvents::RunnerControllerAuditEventService.new(
            scoping, current_user,
            name: 'runner_controller_runner_scope_added',
            message: "Added runner scope for runner ##{runner.id} to runner controller"
          ).track_event
        end

        def scoping_exists?
          runner_controller.runner_level_scoping_exists?(runner.id)
        end

        def error_no_permissions
          ServiceResponse.error(
            message: 'Administrator permission is required to add runner scope',
            reason: :forbidden
          )
        end

        def error_runner_not_instance_type
          ServiceResponse.error(
            message: 'Only instance-type runners can be scoped',
            reason: :unprocessable_entity
          )
        end

        def error_has_instance_scoping
          ServiceResponse.error(
            message: 'Runner controller already has instance-level scope. Remove it before adding runner scopes.',
            reason: :conflict
          )
        end

        def error_already_exists
          ServiceResponse.error(
            message: 'Runner scope already exists for this runner controller',
            reason: :conflict
          )
        end
      end
    end
  end
end
