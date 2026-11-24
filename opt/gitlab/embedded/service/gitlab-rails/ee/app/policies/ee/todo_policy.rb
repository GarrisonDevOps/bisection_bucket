# frozen_string_literal: true

module EE
  module TodoPolicy # rubocop:disable Gitlab/BoundedContexts -- EE extension of the CE TodoPolicy
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      # Only unmask when the expired group SAML session is the *sole* barrier, that is
      # when reauthenticating would grant access. To-dos the user could not read
      # for any other reason (lost membership, confidential target) stay hidden.
      condition(:target_readable_after_group_saml_reauth) do
        target = subject.target
        next false unless target

        readable_after_group_saml_reauth?(:"read_#{target.to_ability_name}")
      end

      rule { own_todo & target_readable_after_group_saml_reauth }.enable :read_todo
    end

    # Internal-note to-dos are dropped by the CE `prevent :read_todo` when the
    # user cannot read the note, which includes the case where only an expired
    # group SAML session blocks it. Keep those readable (masked) too, so the masked
    # list stays consistent with the to-do count.
    override :can_read_internal_note?
    def can_read_internal_note?
      super || readable_after_group_saml_reauth?(:read_internal_note)
    end

    private

    def restricted_by_group_saml?
      resource = subject.project || subject.group

      resource.present? && ::Gitlab::Auth::GroupSaml::SsoEnforcer.access_restricted?(user: user, resource: resource)
    end

    # Re-evaluates `ability` on the to-do's target with group SAML enforcement
    # bypassed, so a to-do blocked only by an expired group SAML session stays
    # readable. Returns false when group SAML is not the barrier, so a check that
    # fails for any other reason keeps denying access.
    #
    # Bypassed results are cached per request in a store separate from the
    # enforced policy cache and safe to share, since every entry is computed
    # with enforcement off. Without it each masked to-do on the page would
    # rebuild the target's whole policy tree.
    def readable_after_group_saml_reauth?(ability)
      target = subject.target
      return false unless target
      return false unless restricted_by_group_saml?

      ::Gitlab::Auth::GroupSaml::SsoEnforcer.bypassing_enforcement do
        cache = ::Gitlab::SafeRequestStore.fetch(:group_saml_bypassed_policy_cache) { {} }
        ::DeclarativePolicy.policy_for(user, target, cache: cache).allowed?(ability)
      end
    end
  end
end
