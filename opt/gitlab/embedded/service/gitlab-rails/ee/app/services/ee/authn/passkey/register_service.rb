# frozen_string_literal: true

module EE
  module Authn
    module Passkey
      module RegisterService
        extend ::Gitlab::Utils::Override

        private

        override :notify_on_success
        def notify_on_success(user, device_name)
          audit_context = {
            name: 'user_enable_passkey',
            author: user,
            scope: user.enterprise_group || user,
            target: user,
            message: 'Registered Passkey',
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
end
