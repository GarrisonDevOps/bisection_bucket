# frozen_string_literal: true

module Members
  class DestroyLdapGroupLinkService
    include ::Gitlab::Allowable

    def self.execute(ldap_group_link, current_user:)
      new(ldap_group_link, current_user).execute
    end

    def initialize(ldap_group_link, current_user)
      @ldap_group_link = ldap_group_link
      @current_user = current_user
    end

    # Wrapping the destroy and the orphaned-provider check (but not the
    # flag reset itself) in the same group-row lock closes a race that
    # existed when destroy and check were separate, unsynchronized steps:
    # two concurrent requests removing different links for the same
    # provider could each see the other's link as still present when
    # checking whether the provider is now orphaned, so neither would
    # trigger the ldap-flag reset. The reset is idempotent and
    # order-independent, so it's safe to run outside the lock once the
    # orphaned decision has been made atomically with the destroy.
    def execute
      return unless authorized?

      orphaned = false
      destroyed = false

      group.with_lock do
        destroyed = !!ldap_group_link.destroy

        orphaned = group.ldap_group_links.with_provider(provider).none?
      end

      audit_destroy if destroyed

      ::Members::ResetOrphanedLdapProviderFlagsService.execute(group, [provider]) if orphaned
    end

    private

    attr_reader :ldap_group_link, :current_user

    def authorized?
      can?(current_user, :delete_ldap_group_link, group)
    end

    def group
      ldap_group_link.group
    end

    def provider
      ldap_group_link.provider
    end

    def audit_destroy
      ::Gitlab::Audit::Auditor.audit(
        name: 'ldap_group_link_removed',
        author: current_user,
        scope: group,
        target: group,
        message: "LDAP group link removed. #{ldap_group_link.identifier_label}, " \
          "Access Level - #{ldap_group_link.human_access}, Provider - #{provider}",
        additional_details: {
          cn: ldap_group_link.cn,
          filter: ldap_group_link.filter,
          group_access: ldap_group_link.human_access,
          provider: provider
        }
      )
    end
  end
end
