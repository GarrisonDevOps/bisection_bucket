# frozen_string_literal: true

module EE
  module Ldap
    module OmniauthCallbacksController
      extend ::Gitlab::Utils::Override

      override :sign_in_and_redirect
      def sign_in_and_redirect(user, *args)
        # The counter gets incremented in `sign_in_and_redirect`
        show_ldap_sync_flash if user.sign_in_count == 0

        super
      end

      override :fail_login
      def fail_login(user)
        # This is the same implementation as EE::OmniauthCallbacksController#fail_login but we need to add it here since
        # we're overriding Ldap::OmniauthCallbacksController#fail_login, not EE::OmniauthCallbacksController#fail_login.
        log_failed_login(user, oauth['provider'])

        super
      end

      private

      override :enqueue_after_sign_in_workers
      def enqueue_after_sign_in_workers(user, auth_user)
        return if auth_user.ldap_config.duo_add_on_groups.blank?

        ::GitlabSubscriptions::AddOnPurchases::LdapAddOnSeatSyncWorker.perform_async({ 'user_id' => user.id })
      end

      def show_ldap_sync_flash
        flash[:notice] = _('LDAP sync in progress. This could take a few minutes. '\
                         'Refresh the page to see the changes.')
      end
    end
  end
end
