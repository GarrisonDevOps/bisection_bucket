# frozen_string_literal: true

module Ci
  module RunnerControllers
    class CreateService
      attr_reader :current_user, :params

      def initialize(current_user:, params:)
        @current_user = current_user
        @params = params
      end

      def execute
        return error_no_permissions unless current_user.can_admin_all_resources?

        controller = ::Ci::RunnerController.new(params)

        if controller.save
          audit_event(controller)
          ServiceResponse.success(payload: controller)
        else
          ServiceResponse.error(message: controller.errors.full_messages.to_sentence, reason: :bad_request)
        end
      end

      private

      def error_no_permissions
        ServiceResponse.error(
          message: 'Administrator permission is required to create a runner controller',
          reason: :forbidden
        )
      end

      def audit_event(controller)
        ::AuditEvents::RunnerControllerAuditEventService.new(
          controller, current_user,
          name: 'runner_controller_created',
          message: "Created runner controller with state #{controller.state}",
          additional_details: { state: controller.state }
        ).track_event
      end
    end
  end
end
