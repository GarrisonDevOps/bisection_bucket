# frozen_string_literal: true

module EE
  module Member
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include SafeFormatHelper

    # Columns read by CachedPlanTier.candidate_root_ids and Member.without_invites_and_requests; keep in sync.
    # The query joins on member_namespace_id, not source_id/source_type as AUTHORIZATION_COLUMNS does.
    # invite_token is left out: it is only cleared on invite acceptance, which sets user_id in the same save.
    PLAN_TIER_COLUMNS = %w[user_id member_namespace_id state requested_at access_level].freeze

    prepended do
      include Elastic::ApplicationVersionedSearch
      include MemberRoles::MemberRoleRelation

      base_access_level_attr :access_level

      state_machine :state, initial: :active do
        event :wait do
          transition active: :awaiting, unless: :last_owner?
        end

        event :activate do
          transition awaiting: :active, if: :has_capacity_left?
        end

        state :awaiting, value: ::Member::STATE_AWAITING
        state :active, value: ::Member::STATE_ACTIVE
      end

      has_many :member_approvals, inverse_of: :member,
        class_name: '::GitlabSubscriptions::MemberManagement::MemberApproval'

      validate :seat_available, on: :create
      validate :seat_type_permits_access_level, if: :enforceable_seat_type_change?

      scope :awaiting, -> { where(state: ::Member::STATE_AWAITING) }
      scope :non_awaiting, -> { where.not(state: ::Member::STATE_AWAITING) }

      scope :banned_from, ->(namespace) do
        sql = "INNER JOIN namespace_bans
               ON namespace_bans.user_id = members.user_id
               AND namespace_bans.namespace_id = ?"
        joins(sanitize_sql_array([sql, namespace.id]))
      end

      scope :not_banned_in, ->(namespace) do
        where.not(user_id: ::Namespaces::NamespaceBan.where(namespace: namespace).select(:user_id))
      end

      scope :with_custom_role, -> { where.not(member_role_id: nil) }
      scope :with_member_role_id, ->(member_role_id) { where(member_role_id: member_role_id) }

      scope :elevated_guests, -> do
        where(access_level: ::Gitlab::Access::GUEST).joins(:member_role).merge(MemberRole.occupies_seat)
      end

      scope :with_elevated_guests, -> do
        non_guests.or(
          where(access_level: ::Gitlab::Access::GUEST)
          .merge(MemberRole.occupies_seat)
        ).left_outer_joins(:member_role)
      end

      scope :count_members_by_role, -> { count_by_access_level }
      scope :count_users_by_role, -> { count_by_access_level('DISTINCT(user_id)') }

      before_create :set_membership_activation

      scope :with_csv_entity_associations, -> do
        includes(:user, source: [:route, :parent])
      end

      scope :distinct_awaiting_or_invited_for_group, ->(group) do
        awaiting
        .or(::Member.invite)
        .in_hierarchy(group)
        .select('DISTINCT ON (members.user_id, members.invite_email) members.*')
        .includes(:user)
        .order(:user_id, :invite_email)
      end

      scope :order_access_level_desc, -> { order(access_level: :desc) }

      after_save :track_plan_tier_changes

      # TODO: revert after https://gitlab.com/gitlab-org/gitlab/-/work_items/638659 is resolved
      after_commit on: [:create, :update, :destroy] do
        expire_cached_plan_tier
      ensure
        @previous_user_ids = nil
        @plan_tier_relevant_change = nil
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override
      include ::Authz::MemberRoleInSharedResource

      # Passing enterprise_group matches its enterprise users' private emails. Callers must
      # first check that the current user can read_email_enterprise_user on that group.
      override :search_by_invite_email_or_user
      def search_by_invite_email_or_user(query, enterprise_group: nil)
        results = super(query)
        return results unless enterprise_group

        email = normalize_invited_search(query).downcase
        return results if email.blank?

        # The email lookup is nested so it drives: it matches at most a couple of users,
        # while a group can have tens of thousands of enterprise users.
        # left_join_users isn't used by this condition; .or needs the same joins as results.
        results.or(
          left_join_users.where(
            user_id: enterprise_group.enterprise_user_details
              .where(user_id: ::User.with_primary_or_secondary_email(email).select(:id))
              .select(:user_id)
          )
        )
      end

      def shared_members_with_member_role(group)
        return ::Member.none unless group.custom_roles_enabled?

        columns = member_columns_for_shared_members_with_member_role

        joins("JOIN group_group_links on members.source_id = group_group_links.shared_with_group_id")
        .joins("JOIN user_group_member_roles on members.user_id = user_group_member_roles.user_id \
          and members.source_id = user_group_member_roles.shared_with_group_id \
          and group_group_links.shared_group_id = user_group_member_roles.group_id")
        .select(columns)
        .where(group_group_links: { shared_group_id: group.self_and_ancestors })
      end

      def member_columns_for_shared_members_with_member_role
        group_group_link_table = ::GroupGroupLink.arel_table

        column_names.map do |column_name|
          case column_name
          when 'access_level'
            args = [group_group_link_table[:group_access], arel_table[:access_level]]
            smallest_value_arel(args, 'access_level')
          when 'member_role_id'
            ::Authz::UserGroupMemberRole.arel_table[:member_role_id]
          else
            arel_table[column_name]
          end
        end
      end

      def highest_role(user, source)
        includes(:member_role)
          .where(source_id: source.self_and_ancestors_ids, user_id: user.id)
          .non_request
          .order(access_level: :desc)
          .first
      end
    end

    override :notification_service
    def notification_service
      if ldap
        # LDAP users shouldn't receive notifications about membership changes
        ::EE::NullNotificationService.new
      else
        super
      end
    end

    override :accept_invite!
    def accept_invite!(new_user)
      return false unless new_user
      return false unless seat_available_for_invite_acceptance?(new_user)

      wait(false) unless source.root_ancestor.capacity_left_for_user?(new_user)

      super
    end

    override :maintaining_elasticsearch?
    def maintaining_elasticsearch?
      ::Gitlab::CurrentSettings.elasticsearch_indexing?
    end

    override :maintain_elasticsearch_create
    def maintain_elasticsearch_create
      return unless user

      ::Elastic::ProcessBookkeepingService.track!(user)
    end

    override :maintain_elasticsearch_update
    def maintain_elasticsearch_update(updated_attributes: previous_changes.keys); end

    override :maintain_elasticsearch_destroy
    def maintain_elasticsearch_destroy
      return unless user

      ::Elastic::ProcessBookkeepingService.track!(user)
    end

    def sso_enforcement
      unless membership_enforcer.can_add_user?(user)
        troubleshoot_link_url = ::Gitlab::Routing.url_helpers.help_page_path(
          'user/group/saml_sso/troubleshooting_scim.md')
        troubleshoot_link = ActionController::Base.helpers.link_to('', troubleshoot_link_url, target: '_blank',
          rel: 'noopener noreferrer')
        msg = safe_format(
          _(
            "is not linked to a SAML account or has an inactive SCIM identity. " \
            "For information on how to resolve this error, see the " \
            "%{troubleshoot_link_start}troubleshooting SCIM documentation%{troubleshoot_link_end}."
          ),
          tag_pair(troubleshoot_link, :troubleshoot_link_start, :troubleshoot_link_end)
        )

        errors.add(:user, msg)
      end
    end

    # The method is exposed in the API as is_using_seat
    # in ee/lib/ee/api/entities.rb
    #
    # rubocop: disable Naming/PredicatePrefix
    def is_using_seat
      return user&.using_gitlab_com_seat?(source) if ::Gitlab.com?

      user&.using_license_seat?
    end
    # rubocop: enable Naming/PredicatePrefix

    def source_kind
      source.is_a?(Group) && source.parent.present? ? 'Sub group' : source.class.to_s
    end

    def group_has_domain_limitations?
      return false unless group

      group.licensed_feature_available?(:group_allowed_email_domains) && group_allowed_email_domains.any?
    end

    def group_domain_limitations
      return unless group

      if user
        return if user.project_bot? || user.security_policy_bot? || user.service_account?

        validate_users_email
        validate_email_verified
      else
        validate_invitation_email
      end
    end

    def group_saml_identity(root_ancestor: false)
      saml_group = root_ancestor ? group.root_ancestor : group

      return unless saml_group.saml_provider

      if user.group_saml_identities.loaded?
        user.group_saml_identities.detect { |i| i.saml_provider_id == saml_group.saml_provider.id }
      else
        user.group_saml_identities.find_by(saml_provider: saml_group.saml_provider)
      end
    end

    def group_scim_identity
      return unless group&.saml_provider

      if user.group_scim_identities.loaded?
        user.group_scim_identities.detect { |i| i.group_id == group.id }
      else
        user.group_scim_identities.find_by(group_id: group.id)
      end
    end

    def update_user_group_member_roles(old_values_map: nil)
      ::Authz::UserGroupMemberRoles::UpdateForGroupMemberService
        .new(self, old_values_map: old_values_map).execute
    end

    override :prevent_role_assignement?
    def prevent_role_assignement?(current_user, params)
      target_member_role_id = params[:member_role_id] || member_role_id

      return true if source.custom_role_abilities_too_high?(
        current_user: current_user,
        target_member_role_id: target_member_role_id
      )

      super
    end

    private

    def expire_cached_plan_tier
      return unless gitlab_saas?

      # Imported members are real users too (Member rejects placeholder users), so they are stuck as well.
      expire_plan_tier_for(user_id, stick: true) if user_id && plan_tier_relevant_change?
      previous_user_ids.each { |previous_user_id| expire_plan_tier_for(previous_user_id, stick: false) }
    end

    def expire_plan_tier_for(id, stick:)
      stick_user_to_primary(id) if stick
      ::GitlabSubscriptions::CachedPlanTier.expire_for_user(id)
    rescue StandardError => e
      ::Gitlab::ErrorTracking.track_exception(e, user_id: id)
    end

    def stick_user_to_primary(id)
      ::User.sticking.stick(:user, id)
    rescue StandardError => e
      ::Gitlab::ErrorTracking.track_exception(e, user_id: id)
    end

    # Runs after every save. saved_changes describes only the last save, so each save's
    # answer is recorded here and read once at commit.
    def track_plan_tier_changes
      previous_user_id = saved_change_to_user_id&.first
      previous_user_ids << previous_user_id if previous_user_id

      record_plan_tier_relevant_change
    end

    # Once any save in the transaction is relevant, later saves can't unset it.
    def record_plan_tier_relevant_change
      @plan_tier_relevant_change ||= previously_new_record? || saved_changes.keys.intersect?(PLAN_TIER_COLUMNS)
    end

    def plan_tier_relevant_change?
      plan_tier_relevant_change_marked? || destroyed?
    end

    def previous_user_ids
      @previous_user_ids ||= []
    end

    def plan_tier_relevant_change_marked?
      @plan_tier_relevant_change
    end

    def gitlab_saas?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end

    def membership_enforcer
      ::Gitlab::Auth::GroupSaml::MembershipEnforcer.new(group)
    end

    def group_allowed_email_domains
      return [] unless group

      group.root_ancestor_allowed_email_domains
    end

    def validate_users_email
      return if matches_at_least_one_group_allowed_email_domain?(user.email)

      errors.add(:user, email_does_not_match_any_allowed_domains(user.email))
    end

    def validate_invitation_email
      return if matches_at_least_one_group_allowed_email_domain?(invite_email)

      errors.add(:invite_email, email_does_not_match_any_allowed_domains(invite_email))
    end

    def validate_email_verified
      return if user.primary_email_verified?

      return if group_saml_identity(root_ancestor: true).present?
      return if group.root_ancestor.scim_identities.for_user(user).exists?

      errors.add(:user, _('is not verified.'))
    end

    def email_does_not_match_any_allowed_domains(email)
      msg_1 = signup_email_invalid_message

      msg_2 = error_message[created_by_key][:group_setting]

      [msg_1, msg_2].join(' ')
    end

    def matches_at_least_one_group_allowed_email_domain?(email)
      group_allowed_email_domains.any? do |allowed_email_domain|
        allowed_email_domain.email_matches_domain?(email)
      end
    end

    def set_membership_activation
      self.state = ::Member::STATE_AWAITING unless has_capacity_left?
    end

    def last_owner?
      source.root_ancestor.last_owner?(self.user)
    end

    def has_capacity_left?
      source.root_ancestor.capacity_left_for_user?(user)
    end

    def seat_available_for_invite_acceptance?(new_user)
      block_seat_overages = ::GitlabSubscriptions::MemberManagement::BlockSeatOverages
      return true unless block_seat_overages.block_seat_overages?(source)

      block_seat_overages.seats_available_for?(source.root_ancestor, [new_user.id], access_level, member_role_id)
    end

    def seat_available
      return unless source # due to source being evaluated during creation, source must be present to evaluate
      return if ::Namespaces::FreeUserCap::Enforcement.new(source.root_ancestor).seat_available?(user)

      msg = format(
        _("cannot be added since you've reached your %{free_limit} member limit for %{namespace_name}"),
        free_limit: ::Namespaces::FreeUserCap.dashboard_limit, namespace_name: source.root_ancestor.name
      )
      errors.add(:base, msg) # add to base here since :user is getting `The member's email address` appended
    end

    def enforceable_seat_type_change?
      access_level_changed? || member_role_id_changed?
    end

    def seat_type_permits_access_level
      return unless ::GitlabSubscriptions::SeatAssignmentModel.enabled?(source)

      seat_assignment = ::GitlabSubscriptions::SeatAssignment
        .find_by_namespace_and_user(source.root_ancestor, user)

      return unless seat_assignment&.seat_type

      return if ::GitlabSubscriptions::SeatTypeRoles.permits_access_level?(
        seat_type: seat_assignment.seat_type,
        access_level: access_level,
        member_role: member_role
      )

      errors.add(:access_level, format(
        _('is not permitted by the seat type. An Owner of %{namespace_name} can change the seat type.'),
        namespace_name: source.root_ancestor.name
      ))
    end

    def validate_member_role_belongs_to_same_root_namespace
      return unless member_role_id && member_namespace.custom_roles_enabled?
      return unless member_role.namespace_id

      return if member_namespace.id == member_role.namespace_id
      return if member_namespace.root_ancestor.id == member_role.namespace_id

      errors.add(:member_namespace, _("must be in same hierarchy as custom role's namespace"))
    end

    override :post_update_hook
    def post_update_hook
      super

      execute_hooks_for(:update) if saved_change_to_access_level? || saved_change_to_expires_at?
    end

    override :post_create_member_hook
    def post_create_member_hook
      super

      execute_hooks_for(:create)
    end

    override :post_create_access_request_hook
    def post_create_access_request_hook
      super

      execute_hooks_for(:request)
    end

    def execute_hooks_for(event)
      return unless source.is_a?(Group)
      return unless source.has_active_hooks?(:member_hooks)

      run_after_commit_or_now do
        data = ::Gitlab::HookData::GroupMemberBuilder.new(self).build(event)
        source.execute_hooks(data, :member_hooks)
      end
    end

    override :after_accept_invite
    def after_accept_invite
      super

      update_user_group_member_roles
    end

    override :after_accept_request
    def after_accept_request
      super

      update_user_group_member_roles
    end
  end
end
