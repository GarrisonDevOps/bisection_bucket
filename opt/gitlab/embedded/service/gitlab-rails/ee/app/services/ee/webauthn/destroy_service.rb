# frozen_string_literal: true

module EE
  module Webauthn # rubocop:disable Gitlab/BoundedContexts -- Overriding existing file
    module DestroyService
      extend ::Gitlab::Utils::Override

      private

      override :notify_on_success
      def notify_on_success(user, device_name)
        audit_context = {
          name: 'user_disable_two_factor',
          author: current_user,
          scope: user&.enterprise_group.presence || user,
          target: user,
          message: 'Deleted WebAuthn device',
          additional_details: {
            device_name: device_name
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)

        super
      end
    end
  end
end
