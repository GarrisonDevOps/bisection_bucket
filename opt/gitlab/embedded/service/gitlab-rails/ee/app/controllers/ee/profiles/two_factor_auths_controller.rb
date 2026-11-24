# frozen_string_literal: true

module EE
  module Profiles
    module TwoFactorAuthsController
      extend ::Gitlab::Utils::Override

      override :show_view_variables
      def show_view_variables
        group_saml_identities = GroupSamlIdentityFinder.new(user: current_user).all

        super.merge(
          group_saml_identities: group_saml_identities
        )
      end

      override :notify_on_success
      def notify_on_success(type, options = {})
        log_audit_event(type, options)

        super
      end

      def log_audit_event(type, options = {})
        message = type == :webauthn ? "WebAuthn device" : "One-time password authenticator"

        audit_context = {
          name: 'user_enable_two_factor',
          author: current_user,
          scope: current_user&.enterprise_group.presence || current_user,
          target: current_user,
          message: "Registered #{message}",
          additional_details: options.dup
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
