# frozen_string_literal: true

module Ci
  module RunnerControllers
    class RevokeTokenService
      attr_reader :token, :current_user

      def initialize(token:, current_user:)
        @token = token
        @current_user = current_user
      end

      def execute
        return error_no_permissions unless current_user.can_admin_all_resources?

        if token.revoke!
          audit_event
          ServiceResponse.success
        else
          ServiceResponse.error(message: token.errors.full_messages.to_sentence, reason: :bad_request)
        end
      end

      private

      def audit_event
        ::AuditEvents::RunnerControllerAuditEventService.new(
          token, current_user,
          name: 'runner_controller_token_revoked',
          message: 'Revoked runner controller token'
        ).track_event
      end

      def error_no_permissions
        ServiceResponse.error(
          message: 'Administrator permission is required to revoke this token',
          reason: :forbidden
        )
      end
    end
  end
end
