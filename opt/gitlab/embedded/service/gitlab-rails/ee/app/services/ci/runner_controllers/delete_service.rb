# frozen_string_literal: true

module Ci
  module RunnerControllers
    class DeleteService
      attr_reader :runner_controller, :current_user

      def initialize(runner_controller:, current_user:)
        @runner_controller = runner_controller
        @current_user = current_user
      end

      def execute
        return error_no_permissions unless current_user.can_admin_all_resources?

        if runner_controller.destroy
          audit_event
          ServiceResponse.success
        else
          ServiceResponse.error(message: runner_controller.errors.full_messages.to_sentence, reason: :bad_request)
        end
      end

      private

      def error_no_permissions
        ServiceResponse.error(
          message: 'Administrator permission is required to delete a runner controller',
          reason: :forbidden
        )
      end

      def audit_event
        ::AuditEvents::RunnerControllerAuditEventService.new(
          runner_controller, current_user,
          name: 'runner_controller_deleted',
          message: 'Deleted runner controller'
        ).track_event
      end
    end
  end
end
