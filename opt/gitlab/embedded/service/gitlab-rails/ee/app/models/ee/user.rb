# frozen_string_literal: true

# rubocop:disable Cop/ActiveRecordDependent -- required by https://gitlab.com/groups/gitlab-org/-/epics/19085
module EE
  # User EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be prepended in the `User` model
  module User
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    include AuditorUserHelper
    include ::GitlabSubscriptions::SubscriptionHelper

    DEFAULT_ROADMAP_LAYOUT = 'months'
    DEFAULT_GROUP_VIEW = 'details'
    ELASTICSEARCH_TRACKED_FIELDS = %w[id username email public_email name admin state
      company timezone external otp_required_for_login].freeze

    FREE_USER_TOP_LEVEL_GROUP_LIMIT = 3
    FREE_USER_TOP_LEVEL_GROUP_LIMIT_FROM_DATE = Date.new(2026, 1, 27)

    prepended do
      include UsageStatistics
      include PasswordComplexity
      include IdentityVerifiable
      include Elastic::ApplicationVersionedSearch
      include Ai::Model
      include Ai::UserAuthorizable

      EMAIL_OPT_IN_SOURCE_ID_GITLAB_COM = 1

      # We aren't using the `auditor?` method for the `if` condition here
      # because `auditor?` returns `false` when the `auditor` column is `true`
      # and the auditor add-on absent. We want to run this validation
      # regardless of the add-on's presence, so we need to check the `auditor`
      # column directly.
      validate :auditor_requires_license_add_on, if: :auditor
      validate :cannot_be_admin_and_auditor

      validate :enterprise_user_email_change, on: :update, if: ->(user) {
        user.email_changed? && user.enterprise_user? && !user.skip_enterprise_user_email_change_restrictions?
      }

      after_create :perform_user_cap_check
      after_create :associate_with_enterprise_group
      after_update :email_changed_hook, if: :saved_change_to_email?
      after_update :dismiss_compromised_password_detection_alerts, if: :saved_change_to_encrypted_password?

      # Runs inside destroy's own transaction, so the FOR UPDATE lock held
      # while checking for another approver survives until the destroy
      # commits or rolls back, closing races between concurrent deletions.
      before_destroy :reassign_protected_environment_approval_rules

      delegate :shared_runners_minutes_limit, :shared_runners_minutes_limit=,
        :extra_shared_runners_minutes_limit, :extra_shared_runners_minutes_limit=,
        to: :namespace
      delegate :onboarding_status_step_url, :onboarding_status_step_url=,
        :onboarding_status_registration_objective, :onboarding_status_registration_objective=,
        :onboarding_status_registration_objective_name,
        :onboarding_status_setup_for_company, :onboarding_status_setup_for_company=,
        :onboarding_status_registration_type, :onboarding_status_registration_type=,
        :onboarding_status_email_opt_in, :onboarding_status_email_opt_in=, :onboarding_status, :onboarding_status=,
        :onboarding_status_initial_registration_type, :onboarding_status_initial_registration_type=,
        :onboarding_status_glm_content, :onboarding_status_glm_content=,
        :onboarding_status_glm_source, :onboarding_status_glm_source=,
        :onboarding_status_joining_project, :onboarding_status_joining_project=, :onboarding_status_role, :onboarding_status_role=, :onboarding_status_role_name,
        :enterprise_group, :enterprise_group=,
        :enterprise_group_id, :enterprise_group_id=, :enterprise_group_associated_at, :enterprise_group_associated_at=,
        to: :user_detail, allow_nil: true

      delegate :enabled_zoekt?, :enabled_zoekt, :enabled_zoekt=,
        :duo_default_namespace_id, :duo_default_namespace_id=,
        :knowledge_graph_governing_namespace_id, :knowledge_graph_governing_namespace_id=,
        to: :user_preference

      delegate :policy_advanced_editor?, :policy_advanced_editor, :policy_advanced_editor=,
        to: :user_preference

      has_many :namespace_ai_user_memories, class_name: 'Ai::NamespaceUserMemory', dependent: :delete_all # rubocop:disable Cop/ActiveRecordDependent -- no callbacks; DB CASCADE is the backstop
      has_many :organization_ai_user_memories, class_name: 'Ai::OrganizationUserMemory', dependent: :delete_all # rubocop:disable Cop/ActiveRecordDependent -- no callbacks; DB CASCADE is the backstop

      has_many :epics,                    foreign_key: :author_id
      has_many :test_reports,             foreign_key: :author_id, inverse_of: :author, class_name: 'RequirementsManagement::TestReport'
      has_many :assigned_epics,           foreign_key: :assignee_id, class_name: "Epic"
      has_many :path_locks,               dependent: :destroy
      has_many :ai_suggested_reviewers, class_name: 'MergeRequests::AiSuggestedReviewer', foreign_key: :user_id,
        inverse_of: :user, dependent: :delete_all
      has_many :vulnerability_feedback, foreign_key: :author_id, class_name: 'Vulnerabilities::Feedback'
      has_many :vulnerability_state_transitions, foreign_key: :author_id, class_name: 'Vulnerabilities::StateTransition', inverse_of: :author
      has_many :vulnerability_severity_overrides, foreign_key: :author_id, class_name: 'Vulnerabilities::SeverityOverride', inverse_of: :author
      has_many :commented_vulnerability_feedback, foreign_key: :comment_author_id, class_name: 'Vulnerabilities::Feedback'
      has_many :merge_requests_compliance_violations,
        foreign_key: :violating_user_id,
        class_name: 'MergeRequests::ComplianceViolation',
        inverse_of: :violating_user,
        dependent: :delete_all

      has_many :boards_epic_user_preferences, class_name: 'Boards::EpicUserPreference', inverse_of: :user
      has_many :epic_board_recent_visits, class_name: 'Boards::EpicBoardRecentVisit', inverse_of: :user

      has_many :approvals, dependent: :destroy

      has_many :minimal_access_group_members, -> { where(requested_at: nil).where(access_level: [::Gitlab::Access::MINIMAL_ACCESS]) }, class_name: 'GroupMember'
      has_many :minimal_access_groups, through: :minimal_access_group_members, source: :group

      has_many :elevated_members, -> { elevated_guests }, class_name: 'Member'

      has_many :requested_member_approvals, class_name: '::GitlabSubscriptions::MemberManagement::MemberApproval', foreign_key: 'requested_by_id'
      has_many :reviewed_member_approvals, class_name: '::GitlabSubscriptions::MemberManagement::MemberApproval', foreign_key: 'reviewed_by_id'

      has_many :users_ops_dashboard_projects
      has_many :ops_dashboard_projects, through: :users_ops_dashboard_projects, source: :project
      has_many :users_security_dashboard_projects
      has_many :security_dashboard_projects, through: :users_security_dashboard_projects, source: :project

      has_many :group_saml_identities, -> { where.not(saml_provider_id: nil) },
        class_name: "::Identity"

      has_many :group_saml_providers, through: :group_saml_identities, source: :saml_provider

      # Protected Branch Access
      has_many :protected_branch_merge_access_levels, dependent: :destroy, class_name: "::ProtectedBranch::MergeAccessLevel"

      has_many :protected_branch_push_access_levels, dependent: :destroy, class_name: "::ProtectedBranch::PushAccessLevel"

      has_many :protected_branch_unprotect_access_levels, dependent: :destroy, class_name: "::ProtectedBranch::UnprotectAccessLevel"

      has_many :deployment_approvals, class_name: 'Deployments::Approval'

      has_many :smartcard_identities

      has_many :group_scim_identities, class_name: 'GroupScimIdentity',
        dependent: :destroy

      has_many :instance_scim_identities, -> { where(group_id: nil) }, class_name: 'ScimIdentity',
        dependent: :destroy
      has_many :scim_group_memberships, -> { where(group_id: nil) }, class_name: 'Authn::ScimGroupMembership'

      has_many :board_preferences, class_name: 'BoardUserPreference', inverse_of: :user

      belongs_to :managing_group, class_name: 'Group', optional: true, inverse_of: :managed_users

      has_many :user_permission_export_uploads
      has_many :user_permission_export_upload_upload_states,
        class_name: 'Geo::UserPermissionExportUploadUploadState',
        foreign_key: :uploaded_by_user_id,
        dependent: :delete_all

      has_many :oncall_participants, -> { not_removed }, class_name: 'IncidentManagement::OncallParticipant', inverse_of: :user
      has_many :oncall_rotations, class_name: 'IncidentManagement::OncallRotation', through: :oncall_participants, source: :rotation
      has_many :oncall_schedules, -> { distinct }, class_name: 'IncidentManagement::OncallSchedule', through: :oncall_rotations, source: :schedule
      has_many :escalation_rules, -> { not_removed }, class_name: 'IncidentManagement::EscalationRule', inverse_of: :user
      has_many :escalation_policies, -> { distinct }, class_name: 'IncidentManagement::EscalationPolicy', through: :escalation_rules, source: :policy

      has_many :namespace_bans, class_name: 'Namespaces::NamespaceBan'

      has_many :workspaces, class_name: 'RemoteDevelopment::Workspace', inverse_of: :user

      has_many :dependency_list_exports, class_name: 'Dependencies::DependencyListExport', inverse_of: :author

      has_many :assigned_add_ons, class_name: '::GitlabSubscriptions::UserAddOnAssignment', inverse_of: :user, dependent: :destroy

      has_many :created_namespace_cluster_agent_mappings,
        class_name: 'RemoteDevelopment::NamespaceClusterAgentMapping',
        inverse_of: :user

      has_many :created_organization_cluster_agent_mappings,
        class_name: 'RemoteDevelopment::OrganizationClusterAgentMapping',
        foreign_key: 'creator_id',
        inverse_of: :user

      has_many :country_access_logs,
        class_name: 'Users::CountryAccessLog',
        inverse_of: :user,
        dependent: :destroy

      has_one :pipl_user, class_name: 'ComplianceManagement::PiplUser'

      has_one :user_admin_role, class_name: 'Authz::UserAdminRole'
      has_one :admin_role, through: :user_admin_role

      # TODO: remove as part of https://gitlab.com/groups/gitlab-org/-/epics/17390
      has_one :user_member_role, class_name: 'Users::UserMemberRole'
      has_one :member_role, class_name: 'MemberRole', through: :user_member_role

      has_many :user_group_member_roles, inverse_of: :user, class_name: 'Authz::UserGroupMemberRole'
      has_many :user_project_member_roles, inverse_of: :user, class_name: 'Authz::UserProjectMemberRole', dependent: :destroy

      has_many :ai_agent_identities,
        class_name: 'Ai::ExternalAgents::AgentIdentity',
        foreign_key: :user_id,
        dependent: :delete_all
      has_many :ai_catalog_item_consumers, class_name: 'Ai::Catalog::ItemConsumer', foreign_key: :service_account_id, dependent: :nullify
      has_many :ai_conversation_threads, class_name: 'Ai::Conversation::Thread', foreign_key: :user_id
      has_many :ai_conversation_messages, class_name: 'Ai::Conversation::Message', through: :ai_conversation_threads, source: :messages
      has_many :ai_catalog_item_versions, class_name: 'Ai::Catalog::ItemVersion', foreign_key: :created_by_id, dependent: :nullify # rubocop:disable Cop/ActiveRecordDependent -- matched FK on_delete
      has_many :ai_catalog_item_stars, class_name: 'Ai::Catalog::ItemStar', dependent: :destroy
      has_many :ai_catalog_mcp_servers_users, class_name: 'Ai::Catalog::McpServersUser', dependent: :destroy
      has_many :created_mcp_servers, class_name: 'Ai::Catalog::McpServer', foreign_key: :created_by_id, dependent: :nullify
      has_many :created_mcp_server_blocks, class_name: 'Ai::Catalog::McpServerBlock', foreign_key: :created_by_id, dependent: :nullify # rubocop:disable Cop/ActiveRecordDependent -- matched FK on_delete
      has_many :created_cd_version_sets, class_name: 'Cd::VersionSet', foreign_key: :created_by_id, dependent: :nullify # rubocop:disable Cop/ActiveRecordDependent -- matched FK on_delete

      has_many :ai_flow_triggers, class_name: 'Ai::FlowTrigger', dependent: :destroy
      has_many :child_item_consumers_flow_triggers, through: :ai_catalog_item_consumers

      has_many :subscription_seat_assignments, class_name: '::GitlabSubscriptions::SeatAssignment'

      has_many :compromised_password_detections, class_name: 'Users::CompromisedPasswordDetection', inverse_of: :user

      has_many :arkose_sessions, class_name: 'Users::ArkoseSession', inverse_of: :user
      has_many :designated_beneficiaries, class_name: 'Users::DesignatedBeneficiary', dependent: :destroy

      has_many :authored_work_item_decisions, class_name: 'WorkItems::Decision', foreign_key: :author_id, dependent: :nullify
      has_many :resolved_work_item_decisions, class_name: 'WorkItems::Decision', foreign_key: :resolved_by_id, dependent: :nullify

      has_many :activation_metrics, class_name: 'Activation::Metric', dependent: :delete_all
      has_many :cluster_agent_url_configurations, class_name: 'Clusters::Agents::UrlConfiguration', foreign_key: :created_by_user_id, dependent: :nullify
      # Only for unmatching people when the user is deleted. Read people through their hierarchy.
      has_many :workforce_people, class_name: 'Workforce::Person', dependent: :nullify # rubocop:disable Cop/ActiveRecordDependent -- matched FK on_delete

      scope :auditors, -> { where('auditor IS true') }

      scope :excluding_guests_and_requests, -> do
        subquery = ::Member
          .select(1)
          .where(::Member.arel_table[:user_id].eq(::User.arel_table[:id]))
          .with_elevated_guests

        subquery = subquery.non_request

        where('EXISTS (?)', subquery)
          .allow_cross_joins_across_databases(url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/422405')
      end

      # This scope is only used on Self-Managed Premium instances.
      # Ultimate instances would use excluding_guests_and_requests instead.
      scope :excluding_minimal_access, -> do
        subquery = ::Member
          .select(1)
          .where(::Member.arel_table[:user_id].eq(::User.arel_table[:id]))
          .non_request
          .group('user_id')
          .having('MAX(access_level) = ?', ::Gitlab::Access::MINIMAL_ACCESS)

        where('NOT EXISTS (?)', subquery)
          .allow_cross_joins_across_databases(url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/422405')
      end

      scope :guests_with_elevating_role, -> do
        joins(:user_highest_role).joins(:elevated_members)
          .where(user_highest_role: { highest_access_level: ::Gitlab::Access::GUEST })
          .allow_cross_joins_across_databases(url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/422405')
      end

      scope :subscribed_for_admin_email, -> { where(admin_email_unsubscribed_at: nil) }

      scope :with_provider, ->(provider) do
        joins(:identities).where(identities: { provider: provider })
      end
      scope :with_saml_provider, ->(saml_provider) do
        joins(:identities).where(identities: { saml_provider: saml_provider })
      end

      scope :with_seat_assignment_in, ->(namespace) do
        joins(:subscription_seat_assignments).where(subscription_seat_assignments: { namespace_id: namespace })
      end

      scope :with_single_sign_on_access_to, ->(group) do
        ::User.from_union([
          all.with_saml_provider(group.saml_provider),
          all.service_account.with_provisioning_group(group.self_and_descendants),
          all.service_account.with_provisioning_project_in(group.self_and_descendants)
        ])
      end

      scope :with_invalid_expires_at_tokens, ->(expiration_date) do
        where(id: ::PersonalAccessToken.with_invalid_expires_at(expiration_date).select(:user_id))
      end

      scope :with_group_scim_identities_by_extern_uid, ->(extern_uid) { joins(:group_scim_identities).merge(GroupScimIdentity.with_extern_uid(extern_uid)) }

      scope :with_instance_scim_identities_by_extern_uid, ->(extern_uid) { joins(:instance_scim_identities).merge(ScimIdentity.with_extern_uid(extern_uid)) }

      scope :with_email_domain, ->(domain) { where("lower(split_part(email, '@', 2)) = ?", domain.downcase) }

      scope :excluding_enterprise_users_of_group, ->(group) { left_join_user_detail.where('user_details.enterprise_group_id != ? OR user_details.enterprise_group_id IS NULL', group.id) }

      scope :security_policy_bots_for_projects, ->(projects) do
        security_policy_bot
          .joins(:members)
          .where(members: { source: projects })
          .allow_cross_joins_across_databases(url: "https://gitlab.com/gitlab-org/gitlab/-/issues/422405")
      end

      scope :orphaned_security_policy_bots, -> do
        security_policy_bot
        .joins("LEFT OUTER JOIN members ON members.user_id = users.id AND members.type = 'ProjectMember'")
        .left_outer_joins(:ghost_user_migration)
        .where(members: { id: nil }, ghost_user_migrations: { id: nil })
      end

      accepts_nested_attributes_for :namespace
      accepts_nested_attributes_for :custom_attributes

      enum :roadmap_layout, { weeks: 1, months: 4, quarters: 12 }

      # User's Group preference
      # Note: When adding an option, it's value MUST equal to the last value + 1.
      enum :group_view, { details: 1, security_dashboard: 2 }, prefix: true
      scope :group_view_details, -> { where('group_view = ? OR group_view IS NULL', group_view[:details]) }
      scope :unconfirmed_and_created_before, ->(created_cut_off) { human.with_state(:active).where(confirmed_at: nil).where('created_at < ?', created_cut_off).where(sign_in_count: 0) }

      # If user cap is reached or restricted access has no seats available,
      # any user that is getting marked :active from :deactivated
      # should get blocked pending approval
      state_machine :state do
        after_transition deactivated: :active do |user|
          user.block_pending_approval if ::User.user_cap_reached?

          if user.seat_limited_on_reactivation?
            user.block_pending_approval
            user.notify_admins_of_dormant_user_blocked
          end
        end
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      def non_ldap
        joins('LEFT JOIN identities ON identities.user_id = users.id')
          .where('identities.provider IS NULL OR identities.provider NOT LIKE ?', 'ldap%')
      end

      def find_by_smartcard_identity(certificate_subject, certificate_issuer)
        joins(:smartcard_identities)
          .find_by(smartcard_identities: { subject: certificate_subject, issuer: certificate_issuer })
      end

      def billable
        scope = active.without_bots

        if License.current&.exclude_guests_from_active_count?
          scope.excluding_guests_and_requests
        else
          scope.excluding_minimal_access
        end
      end

      def non_billable_users_for_billable_management(user_ids)
        # Billable management is done for Ultimate Licenses, so returning None for other Licenses
        return ::User.none unless License.current&.exclude_guests_from_active_count?

        scope = active.without_bots
        billable_user_ids_excluding_lte_guests_and_requests = ::User.select(:id).where(id: user_ids)
                                                       .excluding_guests_and_requests
        scope.where(id: user_ids).where.not(id: billable_user_ids_excluding_lte_guests_and_requests)
      end

      def user_cap_reached?
        return false unless ::Gitlab::CurrentSettings.seat_control_user_cap?

        billable.limit(user_cap_max + 1).count >= user_cap_max
      end

      def user_cap_max
        ::Gitlab::CurrentSettings.new_user_signups_cap
      end

      override :random_password
      def random_password
        1000.times do
          password = super
          next unless complexity_matched? password

          return password
        end
      end

      # override
      def use_separate_indices?
        true
      end

      def filter_items(filter_name)
        case filter_name
        when 'auditors'
          auditors
        else
          super
        end
      end
    end

    def should_use_security_policy_bot_avatar?
      security_policy_bot?
    end

    # Returns the single project this security policy bot belongs to,
    # or nil if the user is not a bot or has zero/multiple memberships (fail closed).
    def security_policy_bot_project
      return unless security_policy_bot?

      memberships = project_members.limit(2).to_a

      return unless memberships.size == 1

      memberships.first.project
    end

    def security_policy_bot_static_avatar_path(size = nil)
      if Avatarable::USER_AVATAR_SIZES.include?(size)
        avatar_image = ActionController::Base.helpers.image_path("bot_avatars/security-bot_#{size}.png")
        return ::Gitlab::Utils.append_path(Settings.gitlab.base_url, avatar_image)
      end

      ::Gitlab::Utils.append_path(Settings.gitlab.base_url, ActionController::Base.helpers.image_path('bot_avatars/security-bot.png'))
    end

    override :toggle_star
    def toggle_star(project)
      super
      project.maintain_elasticsearch_update if self.active? && project.maintaining_elasticsearch?
    end

    def expired_sso_session_saml_providers_with_access_restricted
      expired_sso_session_saml_providers.select do |saml_provider|
        ::Gitlab::Auth::GroupSaml::SsoEnforcer.new(saml_provider, user: self).access_restricted?
      end
    end

    def expired_sso_session_saml_providers
      group_saml_providers.id_not_in(active_sso_sessions_saml_provider_ids)
    end

    def active_sso_sessions_saml_provider_ids
      ::Gitlab::Auth::GroupSaml::SsoEnforcer.sessions_time_remaining_for_expiry.each_with_object([]) do |session, result|
        result << session[:provider_id] if session[:time_remaining] > 0
      end
    end

    def pending_billable_invitations
      if ::License.current.exclude_guests_from_active_count?
        pending_invitations.where('access_level > ?', ::Gitlab::Access::GUEST)
      else
        pending_invitations
      end
    end

    def external?
      return true if security_policy_bot?

      read_attribute(:external)
    end

    def cannot_be_admin_and_auditor
      if admin? && auditor?
        errors.add(:admin, 'user cannot also be an Auditor.')
      end
    end

    def auditor_requires_license_add_on
      unless license_allows_auditor_user?
        errors.add(:auditor, 'user cannot be created without the "GitLab_Auditor_User" addon')
      end
    end

    def auditor?
      self.auditor && license_allows_auditor_user?
    end

    def access_level
      if auditor?
        :auditor
      else
        super
      end
    end

    def access_level=(new_level)
      new_level = new_level.to_s
      return unless %w[admin auditor regular].include?(new_level)

      self.admin = (new_level == 'admin')
      self.auditor = (new_level == 'auditor')
    end

    def email_domain
      Mail::Address.new(email).domain
    end

    def available_custom_project_templates(search: nil, subgroup_id: nil, project_id: nil)
      CustomProjectTemplatesFinder
        .new(current_user: self, search: search, subgroup_id: subgroup_id, project_id: project_id)
        .execute
    end

    def use_elasticsearch?
      ::Gitlab::CurrentSettings.elasticsearch_search?
    end

    override :elastic_reference
    def elastic_reference
      ::Search::Elastic::References::User.serialize(self)
    end

    override :maintaining_elasticsearch?
    def maintaining_elasticsearch?
      ::Gitlab::CurrentSettings.elasticsearch_indexing?
    end

    # override
    def maintain_elasticsearch_update
      super if update_elasticsearch?
    end

    def update_elasticsearch?
      changed_fields = previous_changes.keys
      changed_fields && (changed_fields & ELASTICSEARCH_TRACKED_FIELDS).any?
    end

    def search_membership_ancestry
      members.flat_map do |member|
        member.source&.elastic_namespace_ancestry
      end
    end

    def roadmap_layout
      super || DEFAULT_ROADMAP_LAYOUT
    end

    def group_view
      super || DEFAULT_GROUP_VIEW
    end

    # Returns true if the user owns a group
    # that has never had a trial (now or in the past)
    def owns_group_without_trial?
      owned_groups
        .include_gitlab_subscription
        .top_level
        .where(gitlab_subscriptions: { trial_ends_on: nil })
        .any?
    end

    # Returns true if the user holds a Reporter-or-higher group membership, or
    # (when include_all_memberships: true) any membership (project or group, at
    # any level, including Guest), in a namespace currently on a paid plan.
    def belongs_to_paid_namespace?(plans: ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS, exclude_trials: false, include_all_memberships: false)
      paid_namespaces(
        plans: plans,
        exclude_trials: exclude_trials,
        include_all_memberships: include_all_memberships
      ).any?
    end

    # Returns true if the user is an Owner on any namespace currently on
    # a paid plan
    def owns_paid_namespace?(plans: ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS)
      ::Namespace
        .from("(#{namespace_union_for_owned}) #{::Namespace.table_name}")
        .include_gitlab_subscription
        .where(gitlab_subscriptions: {
          hosted_plan_name_uid: ::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(plans)
        })
        .any?
    end

    def plan_tier
      ::GitlabSubscriptions::CachedPlanTier.for_user_id(id)
    end

    # Root groups where the user has membership (at any level of the group's
    # hierarchy, any role) and the group is entitled to GitLab Credits.
    # DB-level equivalent of Group#gitlab_credits_entitled?
    def groups_with_gitlab_credits
      root_group_ids = groups.roots.select(:id)
      gitlab_credits_plan_names = ::GitlabSubscriptions::Features.saas_plans_with_feature(:group_usage_billing)
      gitlab_credits_plan_uids = ::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(gitlab_credits_plan_names)

      plan_entitled = ::Group.id_in(
        ::GitlabSubscription
          .where(namespace_id: root_group_ids)
          .by_hosted_plan_name_uids(gitlab_credits_plan_uids)
          .select(:namespace_id)
      )

      add_on_entitled = ::Group.id_in(
        ::GitlabSubscriptions::AddOnPurchase
          .for_active_add_ons(:gitlab_credits, nil)
          .where(namespace_id: root_group_ids)
          .select(:namespace_id)
      )

      ::Group.from_union([plan_entitled, add_on_entitled])
    end

    override :has_current_license?
    def has_current_license?
      License.current.present?
    end

    def using_license_seat?
      active? &&
        !internal? &&
        !project_bot? &&
        !service_account? &&
        has_current_license? &&
        paid_in_current_license?
    end

    def using_gitlab_com_seat?(namespace)
      ::Gitlab.com? &&
        namespace.present? &&
        active? &&
        !namespace.root_ancestor.free_plan? &&
        namespace.root_ancestor.billed_user_ids[:user_ids].include?(self.id)
    end

    def assigned_to_duo_enterprise?(container)
      namespace = ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only) ? container.root_ancestor : nil

      ::GitlabSubscriptions::AddOnPurchase
        .for_duo_enterprise
        .active
        .by_namespace(namespace)
        .assigned_to_user(self).exists?
    end

    def assigned_to_duo_pro?(container)
      namespace = ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only) ? container.root_ancestor : nil

      ::GitlabSubscriptions::AddOnPurchase
        .for_duo_pro_or_duo_enterprise
        .active
        .by_namespace(namespace)
        .assigned_to_user(self).exists?
    end

    def group_sso?(group)
      return false unless group

      if group_saml_identities.loaded?
        group_saml_identities.any? { |identity| identity.saml_provider.group_id == group.id }
      else
        group_saml_identities.where(saml_provider: group.saml_provider).any?
      end
    end

    def group_managed_account?
      managing_group.present?
    end

    def managed_by_group?(group)
      return false unless group

      group.domain_verification_available? && enterprise_user_of_group?(group)
    end

    def can_read_email_enterprise_user?(user, group: user_detail.enterprise_group)
      return false unless user && group

      managed_by_group?(group) && Ability.allowed?(user, :read_email_enterprise_user, group)
    end

    def can_disable_two_factor_enterprise_user?(user, group: user_detail.enterprise_group)
      return false unless user && group

      managed_by_group?(group) && Ability.allowed?(user, :disable_two_factor_enterprise_user, group)
    end

    override :ldap_sync_time
    def ldap_sync_time
      ::Gitlab.config.ldap['sync_time']
    end

    override :allow_password_authentication_for_web?
    def allow_password_authentication_for_web?(*)
      return false if group_managed_account?
      return false if password_authentication_disabled_by_enterprise_group?

      super
    end

    override :allow_password_authentication_for_git?
    def allow_password_authentication_for_git?(*)
      return false if group_managed_account?
      return false if password_authentication_disabled_by_enterprise_group?

      super
    end

    override :allow_passkey_authentication?
    def allow_passkey_authentication?
      return false if password_authentication_disabled_by_enterprise_group?

      super
    end

    def password_authentication_disabled_by_enterprise_group?
      return false unless enterprise_user?
      return false unless enterprise_group.saml_provider

      enterprise_group.saml_provider.enabled? && enterprise_group.saml_provider.disable_password_authentication_for_enterprise_users?
    end

    def enterprise_user_of_group?(group)
      enterprise_group_id == group.id
    end

    def enterprise_user?
      # NOTE: Double check is added since enterprise_group_id is a lose foreign key and this is a high traffic method
      # This would make sure that we don't fire a query in most cases on gitlab.com, as we have more normal users than enterprise users.
      enterprise_group_id.present? && enterprise_group.present?
    end

    def gitlab_employee?
      gitlab_team_member?
    end

    def gitlab_team_member?
      human? && gitlab_com_member?
    end

    def gitlab_service_user?
      service_user? && gitlab_com_member?
    end

    def gitlab_bot?
      bot? && gitlab_com_member?
    end

    override :can_access_admin_area?
    def can_access_admin_area?
      return true if super

      has_admin_custom_permissions?
    end
    strong_memoize_attr :can_access_admin_area?

    def security_dashboard
      InstanceSecurityDashboard.new(self)
    end

    # Returns the groups a user has access to, either through a membership or a project authorization
    override :authorized_groups
    def authorized_groups(with_minimal_access: true, include_project_authorizations: true)
      return super unless with_minimal_access

      ::Group.unscoped do
        ::Group.from_union([super, available_minimal_access_groups])
      end
    end

    def exempt_from_top_level_group_limit?
      return true if created_at <= FREE_USER_TOP_LEVEL_GROUP_LIMIT_FROM_DATE
      return true if custom_attributes.by_key(UserCustomAttribute::TOP_LEVEL_GROUP_LIMIT_EXEMPT).exists?
      return true if enterprise_user?
      return true if belongs_to_paid_namespace?(exclude_trials: true)

      false
    end

    def enforce_top_level_group_limit?
      return false unless ::Gitlab::Saas.feature_available?(:enforce_top_level_group_limits)
      return false unless ::Feature.enabled?(:enforce_top_level_group_limits, self)
      return false if exempt_from_top_level_group_limit?

      created_top_level_group_count >= FREE_USER_TOP_LEVEL_GROUP_LIMIT
    end

    def find_or_init_board_epic_preference(board_id:, epic_id:)
      boards_epic_user_preferences.find_or_initialize_by(
        board_id: board_id, epic_id: epic_id)
    end

    # GitLab.com users should not be able to remove themselves
    # when they cannot verify their local password, because it
    # isn't set (using third party authentication).
    override :can_remove_self?
    def can_remove_self?
      return true unless ::Gitlab.com?

      !password_automatically_set?
    end

    def activate_based_on_user_cap?
      !blocked_auto_created_oauth_ldap_user? &&
        blocked_pending_approval? &&
        self.class.user_cap_max.present?
    end

    def blocked_auto_created_oauth_ldap_user?
      identities.any? && block_auto_created_users?
    end

    def privatized_by_abuse_automation?
      # Prevent abuse automation names are expected to be in the format: ghost-:id-:id. Ex: ghost-123-4567
      # More context: https://gitlab.com/gitlab-org/customers-gitlab-com/-/issues/3871 for more context on the
      private_profile? && name.match?(/\Aghost-\d+-\d+\z/)
    end

    def banned_from_namespace?(namespace)
      # Always load the entire collection to allow preloading and avoiding N+1 queries.
      namespace_bans.any? { |namespace_ban| namespace_ban.namespace == namespace }
    end

    def namespace_ban_for(namespace)
      namespace_bans.find_by!(namespace: namespace)
    end

    def registration_audit_details
      {
        id: id,
        username: username,
        name: name,
        email: email,
        access_level: access_level
      }
    end

    override :skip_enterprise_user_email_change_restrictions!
    def skip_enterprise_user_email_change_restrictions!
      @skip_enterprise_user_email_change_restrictions = true # rubocop:disable Gitlab/ModuleWithInstanceVariables
    end

    def skip_enterprise_user_email_change_restrictions?
      @skip_enterprise_user_email_change_restrictions
    end

    def ssh_keys_disabled?
      enterprise_user? && enterprise_group.disable_ssh_keys?
    end

    override :require_ssh_key?
    def require_ssh_key?
      return false if ssh_keys_disabled?

      super
    end

    def contributed_epic_groups
      contributed_group_ids = ::Event.select(:group_id)
        .epic_contributions
        .where(author_id: self)
        .created_after(Time.current - 1.year)
        .distinct
        .without_order

      ::Group.where(id: contributed_group_ids).not_aimed_for_deletion
    end

    def contributed_note_groups
      contributed_group_ids = ::Event.select(:group_id)
        .group_note_contributions
        .where(author_id: self)
        .created_after(Time.current - 1.year)
        .distinct
        .without_order

      ::Group.where(id: contributed_group_ids).not_aimed_for_deletion
    end

    override :allow_user_to_create_group_and_project?
    def allow_user_to_create_group_and_project?
      return false unless ::GitlabSubscriptions::MemberManagement::BlockSeatOverages.seat_upgrade_allowed?(id)

      super
    end

    # For now, we only support max one account manager, but we may change that
    def designated_account_manager
      designated_beneficiaries.manager.last
    end

    # For now, we only support max one account successor, but we may change that
    def designated_account_successor
      designated_beneficiaries.successor.last
    end

    def owned_free_or_trial_groups_with_limit(limit)
      owned_groups.free_or_trial.not_aimed_for_deletion.limit(limit)
    end

    # override, from Devise::Confirmable
    def send_confirmation_instructions
      super

      ::Gitlab::Audit::Auditor.audit({
        name: 'email_confirmation_sent',
        author: self,
        scope: self,
        message: "Confirmation instructions sent to: #{unconfirmed_email}",
        target: self,
        additional_details: {
          target_type: "Email",
          current_email: email,
          unconfirmed_email: unconfirmed_email
        }
      })
    end

    def can_admin_all_namespaces?(namespaces)
      can_admin_all_resources? || namespaces.compact.all? { |ns| Ability.allowed?(self, :admin_namespace, ns) }
    end

    def seat_limited_on_reactivation?
      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        seat_limited_on_reactivation_for_saas?
      else
        seat_limited_on_reactivation_for_self_managed?
      end
    end

    def notify_admins_of_dormant_user_blocked
      run_after_commit do
        ::Users::NotifyDormantUserBlockedWorker.perform_async(id)
      end
    end

    # Skip the write on read-only replicas. On a Geo secondary the UPDATE
    # would raise PG::ReadOnlySqlTransaction and fail sessionless auth on every request.
    override :reset_failed_attempts!
    def reset_failed_attempts!
      return if ::Gitlab::Database.read_only?

      super
    end

    # Set by the private before_destroy callback below. Never computes -
    # reading it before destroy runs, or after a destroy that rolled
    # back, returns an empty array instead of caching a stale answer
    # against state that has since changed.
    def reassigned_protected_environment_approval_rules
      @reassigned_protected_environment_approval_rules || [] # rubocop:disable Gitlab/ModuleWithInstanceVariables
    end

    def available_minimal_access_groups
      return ::Group.none unless License.feature_available?(:minimal_access_role)
      return minimal_access_groups unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      minimal_access_groups.with_feature_available_in_plan(:minimal_access_role)
    end

    protected

    override :password_required?
    def password_required?(*)
      return false if group_managed_account?

      super
    end

    private

    def reassign_protected_environment_approval_rules
      @reassigned_protected_environment_approval_rules = ::ProtectedEnvironment.reassign_sole_user_approver(self) # rubocop:disable Gitlab/ModuleWithInstanceVariables
    end

    def seat_limited_on_reactivation_for_self_managed?
      return false unless ::Gitlab::CurrentSettings.seat_control_block_overages?

      licensed_seats = ::License.current&.seats
      return false unless licensed_seats.present? && licensed_seats.nonzero?

      return false unless ::User.billable.exists?(id)

      ::User.billable.limit(licensed_seats + 1).count > licensed_seats
    end

    def seat_limited_on_reactivation_for_saas?
      group = enterprise_group
      return false unless group
      return false unless group.block_seat_overages?

      subscription = group.gitlab_subscription
      return false unless subscription.has_a_paid_hosted_plan?

      billable_ids = group.billed_user_ids[:user_ids]
      return false unless billable_ids.include?(id)

      billable_ids.count > subscription.seats
    end

    override :self_managed_admin?
    def self_managed_admin?
      super && !::Gitlab::Saas.feature_available?(:admin_homepage)
    end

    def enterprise_user_email_change
      return if user_detail.enterprise_group.owner_of_email?(email)

      errors.add(:email, _("must be owned by the user's enterprise group"))
    end

    def gitlab_com_member?
      ::Gitlab::Com.gitlab_com_group_member?(self)
    end
    strong_memoize_attr :gitlab_com_member?

    def block_auto_created_users?
      if ldap_user?
        provider = ldap_identity.provider

        return false unless provider
        return false unless ::Gitlab::Auth::Ldap::Config.enabled?

        ::Gitlab::Auth::Ldap::Config.new(provider).block_auto_created_users
      else
        ::Gitlab.config.omniauth.block_auto_created_users
      end
    end

    def paid_namespaces(plans: ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS, exclude_trials: false, include_all_memberships: false)
      paid_hosted_plans = ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS & plans

      union = namespace_union_for_membership(
        include_all_memberships: include_all_memberships
      )

      namespaces_with_plans = ::Namespace
        .from("(#{union}) #{::Namespace.table_name}")
        .include_gitlab_subscription
        .where(gitlab_subscriptions: {
          hosted_plan_name_uid: ::GitlabSubscriptions::SystemDefined::Plan.uids_for_names(paid_hosted_plans)
        })

      if exclude_trials
        return namespaces_with_plans
          .where(gitlab_subscriptions: { trial: [nil, false] })
          .or(namespaces_with_plans.where(gitlab_subscriptions: { trial_ends_on: ..Date.yesterday }))
          .select(:id)
      end

      namespaces_with_plans.select(:id)
    end

    def namespace_union_for_owned(select = :id)
      ::Gitlab::SQL::Union.new(
        [
          ::Namespace.select(select).where(type: ::Namespaces::UserNamespace.sti_name, owner: self),
          owned_groups.select(select).top_level
        ]).to_sql
    end

    def namespace_union_for_membership(include_all_memberships: false)
      memberships =
        if include_all_memberships
          member_namespaces.merge(::Member.non_request).select(Arel.sql('namespaces.traversal_ids[1]'))
        else
          reporter_developer_maintainer_owned_groups.select(:id).top_level
        end

      ::Gitlab::SQL::Union.new(
        [
          ::Namespace.select(:id).where(type: ::Namespaces::UserNamespace.sti_name, owner: self),
          memberships
        ],
        remove_duplicates: false
      ).to_sql
    end

    def paid_in_current_license?
      if License.current.exclude_guests_from_active_count? # Ultimate
        highest_role > ::Gitlab::Access::GUEST || elevated_members.any?
      else # Premium
        #
        # As per https://gitlab.com/gitlab-org/gitlab/-/issues/330663#note_2957618576, we will keep
        # users without memberships and users with any roles EXCEPT minimal access billable on
        # self-managed Premium. The long-term goal is to make users without memberships non-billable
        # as well.
        #
        highest_role != ::Gitlab::Access::MINIMAL_ACCESS
      end
    end

    def perform_user_cap_check
      return unless self.class.user_cap_reached?
      return if active?

      run_after_commit do
        SetUserStatusBasedOnUserCapSettingWorker.perform_async(id)
      end
    end

    def associate_with_enterprise_group
      # see callback reasoning: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/130735#note_1556734817
      run_after_commit do
        ::Groups::EnterpriseUsers::AssociateWorker.perform_async(id)
      end
    end

    def email_changed_hook
      run_after_commit do
        if enterprise_user?
          ::Groups::EnterpriseUsers::DisassociateWorker.perform_async(id)
        end
      end
    end

    def dismiss_compromised_password_detection_alerts
      run_after_commit do
        ::Users::CompromisedPasswords::ResolveDetectionForUserService.new(self).execute
      end
    end

    override :should_delay_delete?
    def should_delay_delete?(*args)
      super && !belongs_to_paid_namespace?(exclude_trials: true)
    end

    override :audit_lock_access
    def audit_lock_access(reason: nil)
      return if access_locked?

      if !reason && attempts_exceeded?
        reason = 'excessive failed login attempts'
      end

      ::Gitlab::Audit::Auditor.audit(
        name: 'user_access_locked',
        author: ::Users::Internal.in_organization(organization_id).admin_bot,
        scope: self,
        target: self,
        message: ['User access locked', reason].compact.join(' - ')
      )
    end

    override :audit_unlock_access
    def audit_unlock_access(author: self)
      # We can't use access_locked? because it checks if locked_at <
      # User.unlock_in.ago. If we use access_locked? and the lock is already
      # expired the call to unlock_access! when a user tries to login will not
      # log an audit event as expected
      return unless locked_at.present?

      ::Gitlab::Audit::Auditor.audit(
        name: 'user_access_unlocked',
        author: author,
        scope: self,
        target: self,
        message: 'User access unlocked'
      )
    end

    def has_admin_custom_permissions?
      ::Authz::Admin.new(self).available_permissions_for_user.present?
    end
  end
end
# rubocop:enable Cop/ActiveRecordDependent
