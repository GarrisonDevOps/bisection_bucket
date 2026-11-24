# frozen_string_literal: true

module EE
  module TwoFactor # rubocop:disable Gitlab/BoundedContexts -- Overriding existing file
    module DestroyOtpService
      extend ::Gitlab::Utils::Override

      private

      override :notify_on_success
      def notify_on_success(user)
        audit_context = {
          name: 'user_disable_two_factor',
          author: current_user,
          scope: user&.enterprise_group.presence || user,
          target: user,
          message: 'Disabled One-time password authenticator'
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)

        super
      end
    end
  end
end
