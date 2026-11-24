# frozen_string_literal: true

module Authz
  module Ldap
    class AdminRolesSyncService
      class << self
        def enqueue_sync
          fail_invalid_syncs

          queue_valid_non_running_syncs

          ::Authz::LdapAdminRoleWorker.perform_async
        end

        private

        def queue_valid_non_running_syncs
          ::Authz::LdapAdminRoleLink
            .with_provider(Gitlab::Auth::Ldap::Config.providers)
            .not_running
            .mark_syncs_as_queued
        end

        def fail_invalid_syncs
          # rubocop:disable CodeReuse/ActiveRecord -- Very specific use-case
          ::Authz::LdapAdminRoleLink
            .where.not(provider: Gitlab::Auth::Ldap::Config.providers)
            .mark_syncs_as_failed(_('Provider is invalid'), sync_started_at: DateTime.current)
          # rubocop:enable CodeReuse/ActiveRecord
        end
      end
    end
  end
end
