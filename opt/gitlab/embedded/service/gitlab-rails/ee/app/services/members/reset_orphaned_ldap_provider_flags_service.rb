# frozen_string_literal: true

module Members
  class ResetOrphanedLdapProviderFlagsService
    def self.execute(group, providers)
      new(group, providers).execute
    end

    def initialize(group, providers)
      @group = group
      @providers = providers
    end

    # Once a provider has no group links left for a group, its members'
    # `ldap` flag would otherwise stay stuck at `true` forever (the group
    # falls out of the periodic LDAP group sync's own query, which only
    # selects groups with at least one link, so no future sync would ever
    # touch it again). A stuck flag blocks role/expiration edits via
    # GroupMemberPolicy and silently suppresses membership-change
    # notifications, even though nothing about the member is LDAP-managed
    # anymore.
    #
    # Per GitLab's own documented behavior (doc/user/group/access_and_permissions.md,
    # "Remove group links": "the existing memberships and role assignment
    # are retained"), removing a link must not revoke access, so this
    # resets the stale flag directly rather than re-running the full LDAP
    # group sync, which reconciles membership against current LDAP state
    # and would destroy members no longer entitled by any remaining link.
    def execute
      providers.each do |provider|
        next unless Gitlab::Auth::Ldap::Config.valid_provider?(provider)
        next if group.ldap_group_links.with_provider(provider).exists?

        reset_ldap_flag(provider)
      end
    end

    private

    attr_reader :group, :providers

    def reset_ldap_flag(provider)
      group.all_group_members.of_ldap_type.with_identity_provider(provider)
        .allow_cross_joins_across_databases(url: "https://gitlab.com/gitlab-org/gitlab/-/issues/422405")
        .update_all(ldap: false)
    end
  end
end
