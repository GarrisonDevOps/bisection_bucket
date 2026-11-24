# frozen_string_literal: true

module Ci
  module RunnerControllers
    class CreateTokenService
      attr_reader :runner_controller, :current_user, :params

      def initialize(runner_controller:, current_user:, params:)
        @runner_controller = runner_controller
        @current_user = current_user
        @params = params
      end

      def execute
        return error_no_permissions unless current_user.can_admin_all_resources?

        token = runner_controller.tokens.new(params)

        if token.save
          audit_event(token)
          ServiceResponse.success(payload: token)
        else
          ServiceResponse.error(message: token.errors.full_messages.to_sentence, reason: :bad_request)
        end
      end

      private

      def error_no_permissions
        ServiceResponse.error(
          message: 'Administrator permission is required to create a runner controller token',
          reason: :forbidden
        )
      end

      def audit_event(token)
        ::AuditEvents::RunnerControllerAuditEventService.new(
          token, current_user,
          name: 'runner_controller_token_created',
          message: 'Created runner controller token'
        ).track_event
      end
    end
  end
end
