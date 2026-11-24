# frozen_string_literal: true

module EE
  module GroupMemberPolicy
    extend ActiveSupport::Concern

    prepended do
      with_scope :subject
      condition(:ldap, score: 0) { @subject.ldap? }

      with_scope :subject
      condition(:override, score: 0) { @subject.override? }

      with_scope :subject
      condition(:group_ldap_synced, score: 0) { @subject.group.ldap_synced? }

      rule { ~ldap }.prevent :override_group_member
      # This rule only prevents editing while `group_ldap_synced` is true; once the
      # group stops being LDAP-synced, editing is unblocked even without `override`
      # (which itself becomes unreachable at that point - see GroupPolicy's
      # `rule { ~(ldap_synced & can_manage_ldap) }.prevent :override_group_member`).
      # Approach originally proposed by @dblessing:
      # https://gitlab.com/gitlab-org/gitlab/-/issues/357549#note_900100463
      rule { ldap & ~override & group_ldap_synced }.prevent :update_group_member
    end
  end
end
