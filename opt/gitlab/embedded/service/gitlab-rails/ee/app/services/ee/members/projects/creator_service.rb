# frozen_string_literal: true

module EE
  module Members
    module Projects
      module CreatorService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        private

        override :can_create_new_member?
        def can_create_new_member?
          return false unless service_account_eligible_for_membership?

          if member_user_is_composite_identity_service_account?
            return Ability.allowed?(current_user, :admin_service_account_member, member.project) # rubocop:disable Gitlab/Authz/PermissionCheck -- Match the group member creator authorization for service account membership management.
          end

          return super if adding_the_creator_as_owner_in_a_personal_project?

          # Non-composite-identity service accounts are exempt from the LDAP/SAML membership lock
          # specifically (see doc/user/profile/service_accounts.md#assign-a-service-account-to-a-group-or-project),
          # but unlike composite-identity accounts above, they must still respect other invite
          # restrictions such as `disable_invite_members` -- so this only substitutes for the
          # `admin_project_member` check, and still gets ANDed with `invite_project_members` below.
          # The `else` branch calls `super` rather than repeating its `admin_project_member` check
          # directly: `adding_the_creator_as_owner_in_a_personal_project?` is already known false at
          # this point (handled by the early return above), so `super`'s own `||` against it is a
          # no-op, and this stays in sync with the CE check without a second `rubocop:disable`.
          membership_lock_check =
            if member_user_is_service_account_exempt_from_membership_lock?
              Ability.allowed?(current_user, :admin_service_account_member, member.project) # rubocop:disable Gitlab/Authz/PermissionCheck -- Match the group member creator authorization for service account membership management.
            else
              super
            end

          membership_lock_check && Ability.allowed?(current_user, :invite_project_members, member.project)
        end

        def member_user_is_composite_identity_service_account?
          user = member.user

          return false if user.nil?

          user.composite_ai_service_account?
        end

        def member_user_is_service_account_exempt_from_membership_lock?
          user = member.user

          return false if user.nil?

          user.service_account? && ::Gitlab::CurrentSettings.lock_memberships_to_ldap_or_saml?
        end
      end
    end
  end
end
