# frozen_string_literal: true

module Ci
  module RunnerControllers
    class UpdateService
      attr_reader :runner_controller, :current_user, :params

      def initialize(runner_controller:, current_user:, params:)
        @runner_controller = runner_controller
        @current_user = current_user
        @params = params
      end

      def execute
        return error_no_permissions unless current_user.can_admin_all_resources?

        old_state = runner_controller.state

        if runner_controller.update(params)
          audit_event(old_state)
          ServiceResponse.success(payload: runner_controller)
        else
          ServiceResponse.error(message: runner_controller.errors.full_messages.to_sentence, reason: :bad_request)
        end
      end

      private

      def error_no_permissions
        ServiceResponse.error(
          message: 'Administrator permission is required to update a runner controller',
          reason: :forbidden
        )
      end

      def audit_event(old_state)
        details = {}
        if old_state != runner_controller.state
          details[:state_changed] = { from: old_state, to: runner_controller.state }
        end

        ::AuditEvents::RunnerControllerAuditEventService.new(
          runner_controller, current_user,
          name: 'runner_controller_updated',
          message: build_message(old_state),
          additional_details: details
        ).track_event
      end

      def build_message(old_state)
        return "Updated runner controller" if old_state == runner_controller.state

        "Updated runner controller state from #{old_state} to #{runner_controller.state}"
      end
    end
  end
end
