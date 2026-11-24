# frozen_string_literal: true

module EE
  module Users
    module CreateService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        return error(EE::ApplicationSetting::ERROR_NO_SEATS_AVAILABLE, {}) unless seats_available?

        super
      end

      override :after_create_hook
      def after_create_hook(user, reset_token)
        super

        log_audit_event(user) if audit_required?
      end

      private

      def log_audit_event(user)
        ::Gitlab::Audit::Auditor.audit({
          name: "user_created",
          author: current_user,
          scope: user,
          target: user,
          target_details: user.full_path,
          message: "User #{user.username} created",
          additional_details: {
            add: "user",
            registration_details: user.registration_audit_details
          }
        })
      end

      def audit_required?
        current_user.present?
      end

      def perform_seat_check?
        return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) # only available for SM instances

        ::Gitlab::CurrentSettings.seat_control_block_overages?
      end

      def seats_available?
        return true unless perform_seat_check?
        return true unless user.using_license_seat?

        licensed_seats = License.current.seats

        return true unless licensed_seats.present? && licensed_seats.nonzero?

        ::User.billable.limit(licensed_seats).count < licensed_seats
      end
    end
  end
end
