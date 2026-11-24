# frozen_string_literal: true

module Users
  module CompromisedPasswords
    class ResolveDetectionForUserService
      def initialize(user)
        @user = user
      end

      def execute
        return unless ::Gitlab::Saas.feature_available?(:notify_compromised_passwords)

        increment_metric if resolve_detection?
      end

      private

      attr_reader :user

      def increment_metric
        Gitlab::Metrics
          .counter(
            :compromised_password_detection_passwords_changed,
            'Counter of passwords changed after compromised password detection'
          )
          .increment
      end

      def resolve_detection?
        # Users can only have one unresolved CompromisedPasswordDetection
        detection = user.compromised_password_detections.unresolved.first

        return false if detection.nil?

        detection.resolved_at = Time.current

        return true if detection.save

        Gitlab::AppLogger.error(
          message: "Failed to update CompromisedPasswordDetection",
          errors: detection.errors.full_messages,
          compromised_password_detection_id: detection.id,
          user_id: user.id
        )

        false
      end
    end
  end
end
