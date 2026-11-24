# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    class DeleteNonCompliantUserService
      include ComplianceManagement::Pipl::UserConcern

      def initialize(pipl_user:, current_user:)
        @pipl_user = pipl_user
        @current_user = current_user
      end

      def execute
        authorization_result = authorize!
        return authorization_result if authorization_result

        validation_result = validate!
        return validation_result if validation_result

        pipl_user.user.delete_async(deleted_by: current_user,
          params: { hard_delete: false, skip_authorization: true }.stringify_keys)

        ServiceResponse.success
      end

      private

      attr_reader :pipl_user, :current_user

      delegate :user, to: :pipl_user, private: true

      def authorize!
        unless ::Gitlab::Saas.feature_available?(:pipl_compliance)
          return error_response("Pipl Compliance is not available on this instance")
        end

        return if Ability.allowed?(current_user, :delete_pipl_user, pipl_user)

        error_response("You don't have the required permissions to perform this action or this feature is disabled")
      end

      def validate!
        unless pipl_user.deletion_threshold_met?
          return error_response("Pipl deletion threshold has not been exceeded for user: #{user.id}")
        end

        return error_response("User is not blocked") unless user.blocked?

        return unless user.last_active_at

        return unless user.last_active_at > ComplianceManagement::PiplUser::NOTICE_PERIOD.ago

        error_response("User has activity which is more recent than 60 days")
      end

      def error_response(message)
        ServiceResponse.error(message: message)
      end
    end
  end
end
