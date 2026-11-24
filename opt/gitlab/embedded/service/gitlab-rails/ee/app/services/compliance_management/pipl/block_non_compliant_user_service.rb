# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    class BlockNonCompliantUserService
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

        set_admin_note(user)
        result = ::Users::BlockService.new(current_user).execute(user)

        if result[:status] == :success
          ServiceResponse.success
        else
          error_response(result[:message])
        end
      end

      private

      attr_reader :pipl_user, :current_user

      delegate :user, to: :pipl_user, private: true

      def authorize!
        unless ::Gitlab::Saas.feature_available?(:pipl_compliance)
          return error_response("Pipl Compliance is not available on this instance")
        end

        return if Ability.allowed?(current_user, :block_pipl_user, pipl_user)

        error_response("You don't have the required permissions to perform this action or this feature is disabled")
      end

      def validate!
        return error_response("User belongs to a paid group") if belongs_to_paid_group?(user)

        return if pipl_user.block_threshold_met?

        error_response("Pipl block threshold has not been exceeded for user: #{user.id}")
      end

      def error_response(message)
        ServiceResponse.error(message: message)
      end

      def set_admin_note(user)
        msg = _("User was blocked due to the %{days}-day PIPL compliance block threshold being reached")
        user.add_admin_note(format(msg, days: PiplUser::NOTICE_PERIOD / 1.day))
      end
    end
  end
end
