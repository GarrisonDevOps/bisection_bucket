# frozen_string_literal: true

module Gitlab
  module Scim
    class DeprovisioningService < BaseDeprovisioningService
      def execute
        ScimIdentity.transaction do
          identity.update!(active: false)
          block_user(user)
        end

        ServiceResponse.success(message: format(_("User %{user} SCIM identity is deactivated"), user: user.name))
      end

      private

      def block_user(user)
        return unless user.system_block

        log_audit_event_for_block(user)
      end

      def log_audit_event_for_block(user)
        ::Gitlab::Audit::Auditor.audit(
          name: 'user_blocked_by_scim_deprovisioning',
          message: 'Blocked user by SCIM deprovisioning',
          author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          scope: user,
          target: user,
          target_details: user.username,
          additional_details: {
            system_event: true,
            reason: 'deprovisioned via SCIM',
            extern_uid: identity.extern_uid
          }
        )
      end
    end
  end
end
