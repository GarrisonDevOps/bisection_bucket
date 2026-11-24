# frozen_string_literal: true

module ComplianceManagement
  module Pipl
    class SendInitialComplianceEmailService
      def initialize(user:)
        @user = user
      end

      def execute
        return error_response("User does not exist") unless user
        return error_response("Pipl user record does not exist") unless pipl_user.present?
        return error_response("Feature 'enforce_pipl_compliance' is disabled") unless enforce_pipl_compliance?
        return error_response("Initial email has already been sent") if initial_email_sent?

        pipl_user.update!(initial_email_sent_at: Time.current)

        Notify
          .pipl_compliance_notification(user, pipl_user.pipl_access_end_date)
          .deliver_later

        ServiceResponse.success
      end

      private

      attr_reader :user

      delegate :pipl_user, to: :user, private: true

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
