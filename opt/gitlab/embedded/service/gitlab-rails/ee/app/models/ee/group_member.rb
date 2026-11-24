# frozen_string_literal: true

module EE
  module GroupMember
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    prepended do
      include UsageStatistics

      validate :sso_enforcement, if: -> { group && user }
      validate :group_domain_limitations, if: :group_has_domain_limitations?
      validate :validate_no_security_policy_bot_as_group_member

      scope :by_group_ids, ->(group_ids) { where(source_id: group_ids) }

      scope :with_ldap_dn, -> do
        joins(user: :identities).where("identities.provider LIKE ?", 'ldap%')
        .allow_cross_joins_across_databases(url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/422405')
      end

      scope :with_identity_provider, ->(provider) do
        joins(user: :identities).where(identities: { provider: provider })
      end

      scope :with_saml_identity, ->(provider) do
        joins(user: :identities).where(identities: { saml_provider_id: provider })
        .allow_cross_joins_across_databases(url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/422405')
      end

      scope :reporters, -> { where(access_level: ::Gitlab::Access::REPORTER) }
      scope :guests, -> { where(access_level: ::Gitlab::Access::GUEST) }
      scope :by_user_id, ->(user_id) { where(user_id: user_id) }

      scope :eligible_approvers_ids_by_groups, ->(groups) do
        where(source_id: groups.pluck(:id), access_level: ::Gitlab::Access::DEVELOPER...)
          .select(:user_id)
          .limit(::Security::ScanResultPolicy::APPROVERS_LIMIT)
      end

      scope :eligible_approvers_ids_by_group_ids_and_custom_roles, ->(group_ids, custom_roles) do
        where(source_id: group_ids, member_role_id: custom_roles)
          .select(:user_id)
          .limit(Security::ScanResultPolicy::APPROVERS_LIMIT)
      end

      attr_accessor :ignore_user_limits
    end

    class_methods do
      def member_of_group?(group, user)
        exists?(group: group, user: user)
      end

      def direct_member_of_groups?(group_ids, user)
        active_without_invites_and_requests
          .non_minimal_access
          .where(source_id: group_ids)
          .exists?(user_id: user.id)
      end

      def filter_by_enterprise_users(value)
        subquery =
          ::UserDetail.where(
            ::UserDetail.arel_table[:enterprise_group_id].eq(arel_table[:source_id]).and(
              ::UserDetail.arel_table[:user_id].eq(arel_table[:user_id]))
          )

        if value
          where_exists(subquery)
        else
          where_not_exists(subquery)
        end.allow_cross_joins_across_databases(url: "https://gitlab.com/gitlab-org/gitlab/-/issues/419933")
      end
    end

    def enterprise_user_of_this_group?
      user&.user_detail&.enterprise_group_id == source_id
    end

    # Last gate for an invite created before the LDAP/SAML membership lock was
    # enabled: the creation-time GroupPolicy guard never fired, so acceptance
    # must re-check. There is no service-account exemption here (unlike the
    # creation path): acceptance carries no acting user whose
    # `admin_service_account_member` ability could authorize it, and service
    # accounts join through direct member creation, not stale email invites.
    override :accept_invite!
    def accept_invite!(new_user)
      return false if source.instance_membership_lock_applies?

      super
    end

    private

    override :access_level_inclusion
    def access_level_inclusion
      levels = source.access_level_values
      return if access_level.in?(levels)

      errors.add(:access_level, "is not included in the list")

      if access_level == ::Gitlab::Access::MINIMAL_ACCESS
        errors.add(:access_level, "supported on top level groups only") if group.has_parent?
        errors.add(:access_level, "not supported by license") unless group.feature_available?(:minimal_access_role)
      end
    end

    override :post_destroy_member_hook
    def post_destroy_member_hook
      super

      execute_hooks_for(:destroy)
    end

    override :post_destroy_access_request_hook
    def post_destroy_access_request_hook
      super

      execute_hooks_for(:revoke)
    end

    override :seat_available
    def seat_available
      return if ignore_user_limits

      super
    end

    def validate_no_security_policy_bot_as_group_member
      return unless user&.security_policy_bot?

      errors.add(:member_user_type, _("Security policy bot cannot be added as a group member"))
    end
  end
end
