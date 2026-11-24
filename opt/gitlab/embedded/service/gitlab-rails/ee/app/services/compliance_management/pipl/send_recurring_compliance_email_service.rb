# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    class SendRecurringComplianceEmailService
      include ComplianceManagement::Pipl::UserConcern

      PIPL_COMPLIANCE_MESSAGE = "User is not subject to PIPL " \
        "or the initial email has yet to be sent"

      def initialize(user:)
        @user = user
      end

      def execute
        unless ::Gitlab::Saas.feature_available?(:pipl_compliance)
          return error_response("Pipl Compliance is not available on this instance")
        end

        return error_response("User does not exist") unless user
        return error_response("Pipl user record does not exist") unless pipl_user.present?
        return error_response("Feature 'enforce_pipl_compliance' is disabled") unless enforce_pipl_compliance?
        return error_response(PIPL_COMPLIANCE_MESSAGE) unless initial_email_sent?
        return error_response("User is paid") if belongs_to_paid_group?(user)

        Notify.pipl_compliance_notification(user, pipl_user.pipl_access_end_date).deliver_later
        ServiceResponse.success
      end

      private

      attr_reader :user

      delegate :pipl_user, to: :user

      def error_response(message)
        ServiceResponse.error(message: message)
      end

      def initial_email_sent?
        pipl_user.initial_email_sent_at.present?
      end

      def enforce_pipl_compliance?
        ::Gitlab::CurrentSettings.enforce_pipl_compliance?
      end
    end
  end
end
