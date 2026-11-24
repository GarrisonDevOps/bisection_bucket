# frozen_string_literal: true

module Ci
  module RunnerControllers
    module Scopes
      class AddInstanceService
        attr_reader :runner_controller, :current_user

        def initialize(runner_controller:, current_user:)
          @runner_controller = runner_controller
          @current_user = current_user
        end

        def execute
          return error_no_permissions unless current_user.can_admin_all_resources?
          return error_already_exists if runner_controller.instance_level_scoping.present?
          return error_has_runner_scopings if runner_controller.runner_level_scopings.exists?

          scoping = runner_controller.build_instance_level_scoping

          if scoping.save
            audit_event(scoping)
            ServiceResponse.success(payload: scoping)
          else
            ServiceResponse.error(message: scoping.errors.full_messages.to_sentence, reason: :bad_request)
          end
        end

        private

        def audit_event(scoping)
          ::AuditEvents::RunnerControllerAuditEventService.new(
            scoping, current_user,
            name: 'runner_controller_instance_scope_added',
            message: 'Added instance-level scope to runner controller'
          ).track_event
        end

        def error_no_permissions
          ServiceResponse.error(
            message: 'Administrator permission is required to add instance-level scope',
            reason: :forbidden
          )
        end

        def error_already_exists
          ServiceResponse.error(
            message: 'Instance-level scope already exists for this runner controller',
            reason: :conflict
          )
        end

        def error_has_runner_scopings
          ServiceResponse.error(
            message: 'Runner controller already has runner-level scopes. ' \
              'Remove them before adding instance-level scope.',
            reason: :conflict
          )
        end
      end
    end
  end
end
