# frozen_string_literal: true

module Ci
  module RunnerControllers
    class RotateTokenService
      attr_reader :token, :current_user

      def initialize(token:, current_user:)
        @token = token
        @current_user = current_user
      end

      def execute
        return error_no_permissions unless current_user.can_admin_all_resources?
        return ServiceResponse.error(message: 'Token already revoked', reason: :bad_request) if token.revoked?

        response = ServiceResponse.success
        new_token = nil

        ::Ci::RunnerControllerToken.transaction do
          unless token.revoke!
            response = ServiceResponse.error(message: 'Failed to revoke token', reason: :bad_request)
            raise ActiveRecord::Rollback
          end

          new_token = ::Ci::RunnerControllerToken.new(
            runner_controller: token.runner_controller,
            description: token.description
          )

          if new_token.save
            response = ServiceResponse.success(payload: new_token)
          else
            response = ServiceResponse.error(message: new_token.errors.full_messages.to_sentence, reason: :bad_request)
            raise ActiveRecord::Rollback
          end
        end

        audit_event(new_token) if response.success?

        response
      end

      private

      def audit_event(new_token)
        ::AuditEvents::RunnerControllerAuditEventService.new(
          new_token, current_user,
          name: 'runner_controller_token_rotated',
          message: 'Rotated runner controller token'
        ).track_event
      end

      def error_no_permissions
        ServiceResponse.error(
          message: 'Administrator permission is required to rotate this token',
          reason: :forbidden
        )
      end
    end
  end
end
