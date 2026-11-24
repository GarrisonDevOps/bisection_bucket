# frozen_string_literal: true

module EE
  # Group EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be included in the `Group` model
  module Group
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include TokenAuthenticatable
      include InsightsFeature
      include HasWiki
      include ::WebHooks::HasWebHooks
      include CanMoveRepositoryStorage
      include ReactiveCaching
      include ::WorkItems::Parent
      include Elastic::MaintainElasticsearchOnGroupUpdate
      include ProductAnalyticsHelpers
      include ::Ai::CustomizablePermission
      include ::Elastic::ApplicationVersionedSearch
      include ::GitlabSubscriptions::Billing::Group

      ALLOWED_ACTIONS_TO_USE_FILTERING_OPTIMIZATION = [:read_epic, :read_confidential_epic, :read_work_item, :read_confidential_issues].freeze
      EPIC_BATCH_SIZE = 500

      self.reactive_cache_work_type = :no_dependency
      self.reactive_cache_refresh_interval = 10.minutes
      self.reactive_cache_lifetime = 1.hour

      add_authentication_token_field :saml_discovery_token, insecure: true, unique: false, token_generator: -> { Devise.friendly_token(8) } # rubocop:disable Gitlab/TokenWithoutPrefix -- wontfix; not used for authentication

      has_many :epics
      has_many :epic_boards, class_name: 'Boards::EpicBoard', inverse_of: :group
      has_many :iterations
      has_many :iterations_cadences, class_name: 'Iterations::Cadence'
      has_one :saml_provider
      has_many :ip_restrictions, autosave: true
      has_many :protected_environments, inverse_of: :group

      # Reassigns this group's sole-approver rules rather than blocking
      # destroy, which would let a hostile Guest permanently lock the
      # group by making it a rule's sole approver.
      before_destroy :reassign_protected_environment_approval_rules

      has_one :insight, foreign_key: :namespace_id
      has_one :value_stream_dashboard_aggregation, class_name: 'Analytics::ValueStreamDashboard::Aggregation', foreign_key: :namespace_id
      accepts_nested_attributes_for :insight, allow_destroy: true
      has_one :analytics_dashboards_pointer, class_name: 'Analytics::Dashboards::DashboardsPointer', foreign_key: :namespace_id
      accepts_nested_attributes_for :analytics_dashboards_pointer, allow_destroy: true
      accepts_nested_attributes_for :value_stream_dashboard_aggregation, update_only: true
      has_one :analytics_dashboards_configuration_project, through: :analytics_dashboards_pointer, source: :target_project
      # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
      has_one :index_status, class_name: 'Elastic::GroupIndexStatus', foreign_key: :namespace_id, dependent: :destroy
      # rubocop:enable Cop/ActiveRecordDependent -- legacy usage
      has_one :google_cloud_platform_workload_identity_federation_integration, class_name: 'Integrations::GoogleCloudPlatform::WorkloadIdentityFederation'
      has_one :amazon_q_integration, class_name: 'Integrations::AmazonQ'
      has_one :vulnerability_namespace_statistic, class_name: 'Vulnerabilities::NamespaceStatistic', foreign_key: :namespace_id, inverse_of: :group
      has_many :external_audit_event_destinations, class_name: "AuditEvents::ExternalAuditEventDestination", foreign_key: 'namespace_id'
      has_many :external_audit_event_streaming_destinations, class_name: "AuditEvents::Group::ExternalStreamingDestination", foreign_key: 'group_id'
      has_many :google_cloud_logging_configurations, class_name: "AuditEvents::GoogleCloudLoggingConfiguration",
        foreign_key: 'namespace_id',
        inverse_of: :group
      has_many :amazon_s3_configurations, class_name: "AuditEvents::AmazonS3Configuration",
        foreign_key: 'namespace_id',
        inverse_of: :group

      has_many :ldap_group_links, foreign_key: 'group_id', dependent: :destroy # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
      has_many :saml_group_links, foreign_key: 'group_id'
      has_many :hooks, class_name: 'GroupHook'

      has_many :allowed_email_domains, -> { order(id: :asc) }, autosave: true

      has_many :scim_identities, class_name: 'GroupScimIdentity'
      has_one :scim_auth_access_token, class_name: 'GroupScimAuthAccessToken'

      has_many :managed_users, class_name: 'User', foreign_key: 'managing_group_id', inverse_of: :managing_group
      has_many :enterprise_user_details, class_name: 'UserDetail', foreign_key: 'enterprise_group_id', inverse_of: :enterprise_group
      has_many :enterprise_users, through: :enterprise_user_details, source: :user
      has_one :group_merge_request_approval_setting, inverse_of: :group

      has_one :group_wiki_repository
      has_many :repository_storage_moves, class_name: 'Groups::RepositoryStorageMove', inverse_of: :container

      has_many :epic_board_recent_visits, class_name: 'Boards::EpicBoardRecentVisit', inverse_of: :group
      has_many :ssh_certificates, inverse_of: :group, foreign_key: :namespace_id, class_name: 'Groups::SshCertificate'

      has_one :group_push_rule, inverse_of: :group, foreign_key: 'group_id'

      has_many :approval_rules, class_name: 'ApprovalRules::ApprovalGroupRule', inverse_of: :group

      has_many :saved_replies, class_name: 'Groups::SavedReply'

      has_many :security_exclusions, class_name: 'Security::GroupSecurityExclusion'

      # WIP v2 approval rules as part of https://gitlab.com/groups/gitlab-org/-/epics/12955
      has_many :v2_approval_rules_groups, class_name: 'MergeRequests::ApprovalRulesGroup', inverse_of: :group
      has_many :v2_approval_rules, through: :v2_approval_rules_groups, class_name: 'MergeRequests::ApprovalRule', source: :approval_rule

      has_many :subscription_seat_assignments, class_name: '::GitlabSubscriptions::SeatAssignment', foreign_key: :namespace_id

      has_many :analyzer_group_statuses, class_name: 'Security::AnalyzerNamespaceStatus', foreign_key: :namespace_id, inverse_of: :namespace
      has_many :security_scan_profiles, class_name: 'Security::ScanProfile', foreign_key: :namespace_id, inverse_of: :namespace
      has_many :ai_feature_settings, class_name: 'Ai::ModelSelection::NamespaceFeatureSetting', foreign_key: :namespace_id, inverse_of: :namespace
      has_many :configured_ai_catalog_items, class_name: '::Ai::Catalog::ItemConsumer', inverse_of: :group

      has_one :secrets_manager, class_name: '::SecretsManagement::GroupSecretsManager', inverse_of: :group
      has_many :group_secret_rotation_infos, class_name: '::SecretsManagement::GroupSecretRotationInfo', inverse_of: :group

      has_one :namespace_template_setting, class_name: 'Namespaces::TemplateSetting',
        foreign_key: :namespace_id, autosave: true, inverse_of: :namespace
      has_one :file_template_project, through: :namespace_template_setting, class_name: 'Project'

      delegate :repository_read_only,
        :default_compliance_framework,
        :default_compliance_framework_id,
        to: :namespace_settings, allow_nil: true

      delegate :duo_availability, :duo_availability=, to: :namespace_settings
      delegate :duo_remote_flows_availability, :duo_remote_flows_availability=, to: :namespace_settings
      delegate :duo_foundational_flows_availability, :duo_foundational_flows_availability=, to: :namespace_settings
      delegate :duo_scheduled_triggers_availability, :duo_scheduled_triggers_availability=, to: :namespace_settings
      delegate :duo_custom_agents_availability, :duo_custom_agents_availability=, to: :namespace_settings
      delegate :duo_custom_flows_availability, :duo_custom_flows_availability=, to: :namespace_settings
      delegate :tool_approval_for_session_availability, :tool_approval_for_session_availability=, to: :namespace_settings
      delegate :duo_auto_mode_availability, :duo_auto_mode_availability=, to: :namespace_settings
      delegate :experiment_settings_allowed?, :prompt_cache_settings_allowed?, to: :namespace_settings
      delegate :user_cap_enabled?, to: :namespace_settings

      delegate :disable_personal_access_tokens=, to: :namespace_settings
      delegate :disable_ssh_keys=, to: :namespace_settings
      delegate :hide_email_on_profile=, to: :namespace_settings
      delegate :hide_email_on_profile?, to: :namespace_settings
      delegate :allow_personal_snippets, to: :namespace_settings
      delegate :allow_personal_snippets=, to: :namespace_settings
      delegate :allow_personal_snippets?, to: :namespace_settings
      delegate :allow_enterprise_user_account_deletion, to: :namespace_settings
      delegate :allow_enterprise_user_account_deletion=, to: :namespace_settings
      delegate :allow_enterprise_user_account_deletion?, to: :namespace_settings

      delegate :policy_store_experiment_enabled, to: :namespace_settings
      delegate :policy_store_experiment_enabled=, to: :namespace_settings
      delegate :policy_store_experiment_enabled?, to: :namespace_settings

      delegate :enterprise_users_extensions_marketplace_enabled=, to: :namespace_settings

      delegate :wiki_access_level, :wiki_access_level=, to: :group_feature, allow_nil: true

      delegate :extended_grat_expiry_webhooks_execute, :extended_grat_expiry_webhooks_execute=, to: :namespace_settings

      delegate :disable_invite_members, :disable_invite_members=, to: :namespace_settings
      delegate :disable_invite_members?, to: :namespace_settings

      delegate :mcp_server_enabled, :mcp_server_enabled=, to: :namespace_settings, allow_nil: true

      # Use +checked_file_template_project+ instead, which implements important
      # visibility checks
      private :file_template_project

      # Set in batch by Search::Elastic::References::Group.preload_indexing_data, so
      # serializing a batch does not walk the hierarchy once per record.
      attr_accessor :elastic_active

      scope :preload_indexing_data, -> {
        preload(
          :route,
          :parent,
          :namespace_settings,
          :namespace_details
        )
      }

      # Opportunistically clear the +file_template_project_id+ if invalid
      before_validation :clear_file_template_project_id

      validates :repository_size_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, allow_nil: true }

      scope :with_saml_provider, -> { preload(:saml_provider) }
      scope :with_saml_group_links, -> { joins(:saml_group_links) }
      scope :with_mcp_server_enabled, -> do
        joins(:namespace_settings).where(namespace_settings: { mcp_server_enabled: true })
      end
      scope :with_knowledge_graph_enabled_namespace, -> { joins(:knowledge_graph_enabled_namespace) }
      scope :with_knowledge_graph_excluded_namespace, -> do
        joins(:knowledge_graph_excluded_namespace).ordered_by_name
      end
      scope :root_namespaces_without_knowledge_graph_enabled_namespace, -> do
        top_level.left_outer_joins(:knowledge_graph_enabled_namespace)
          .left_outer_joins(:knowledge_graph_excluded_namespace)
          .where(knowledge_graph_enabled_namespace: { root_namespace_id: nil })
          .where(knowledge_graph_excluded_namespace: { root_namespace_id: nil })
      end

      # Duo Agent Platform is on unless the top-level group turned it off, so only explicit opt-outs are excluded.
      scope :with_duo_agent_platform_enabled, -> do
        disabled_root_settings = ::Ai::NamespaceSetting
          .feature_settings_where(duo_agent_platform_enabled: false)
          .where('namespace_ai_settings.namespace_id = namespaces.traversal_ids[1]')
          .select(1)

        where('NOT EXISTS (?)', disabled_root_settings)
      end

      scope :where_group_links_with_provider, ->(provider) do
        joins(:ldap_group_links).where(ldap_group_links: { provider: provider })
      end

      scope :invited_groups_in_groups_for_hierarchy, ->(group, exclude_guests = false) do
        guests_scope = exclude_guests ? ::GroupGroupLink.non_guests : ::GroupGroupLink.all

        joins(:shared_group_links)
          .where(group_group_links: { shared_group_id: group.self_and_descendants })
          .merge(guests_scope)
      end

      scope :invited_groups_with_guest_member_role, ->(group) do
        joins(:shared_group_links)
          .where(group_group_links: { shared_group_id: group.self_and_descendants })
          .merge(::GroupGroupLink.guests.with_custom_role)
      end

      scope :invited_groups_in_projects_for_hierarchy, ->(group, exclude_guests = false) do
        guests_scope = exclude_guests ? ::ProjectGroupLink.non_guests : ::ProjectGroupLink.all

        joins(:project_group_links)
          .where(project_group_links: { project_id: group.all_projects })
          .merge(guests_scope)
      end

      scope :with_external_audit_event_destinations, -> do
        joins(:external_audit_event_destinations)
      end

      scope :with_managed_accounts_enabled, -> do
        joins(:saml_provider).where(saml_providers:
          {
            enabled: true,
            enforced_sso: true,
            enforced_group_managed_accounts: true
          })
      end

      scope :with_project_templates, -> {
        joins(:namespace_template_setting).merge(::Namespaces::TemplateSetting.with_custom_project_templates)
      }

      scope :with_custom_file_templates, -> do
        where(
          id: ::Namespaces::TemplateSetting.where.not(file_template_project_id: nil).select(:namespace_id)
        ).preload_file_templates
         .preload(projects: :route, shared_projects: :route)
      end

      # Preloads namespace_template_setting for use with checked_file_template_project
      # without altering query ordering (used by CustomFileTemplates).
      scope :preload_file_templates, -> do
        preload(namespace_template_setting: { file_template_project: :route })
      end

      # Returns groups with public or internal visibility_level.
      # Used by Group.groups_user_can method to include groups
      # where user access_level does not need to be checked.
      scope :not_private, -> { with_visibility_level_greater_than(::Gitlab::VisibilityLevel::PRIVATE) }

      scope :for_epics, ->(epics) do
        epics_query = epics.select(:group_id)
        joins("INNER JOIN (#{epics_query.to_sql}) as epics on epics.group_id = namespaces.id")
      end

      scope :user_is_member, ->(user) { id_in(user.authorized_groups(with_minimal_access: false)) }

      scope :by_repository_storage, ->(storage) do
        joins(group_wiki_repository: :shard).where(shards: { name: storage })
      end

      scope :not_indexed_in_elasticsearch, -> { left_joins(:index_status).where(index_status: { namespace_id: nil }) }

      scope :with_duo_template_project, -> {
        joins(:namespace_template_setting)
          .includes(namespace_template_setting: :duo_template_project)
          .where.not(namespace_template_settings: { duo_template_project_id: nil })
      }

      state_machine :ldap_sync_status, namespace: :ldap_sync, initial: :ready do
        state :ready
        state :started
        state :pending
        state :failed

        event :pending do
          transition [:ready, :failed] => :pending
        end

        event :start do
          transition [:ready, :pending, :failed] => :started
        end

        event :finish do
          transition started: :ready
        end

        event :fail do
          transition started: :failed
        end

        after_transition ready: :started do |group, _|
          group.ldap_sync_last_sync_at = DateTime.current
          group.save
        end

        after_transition started: :ready do |group, _|
          current_time = DateTime.current
          group.ldap_sync_last_update_at = current_time
          group.ldap_sync_last_successful_update_at = current_time
          group.ldap_sync_error = nil
          group.save
        end

        after_transition started: :failed do |group, _|
          group.ldap_sync_last_update_at = DateTime.current
          group.save
        end
      end

      def enforced_group_managed_accounts?
        !!saml_provider&.enforced_group_managed_accounts?
      end

      def enforced_sso?
        !!saml_provider&.enforced_sso?
      end

      def repository_read_only?
        !!namespace_settings&.repository_read_only?
      end

      def unique_project_download_limit_enabled?
        root? && licensed_feature_available?(:unique_project_download_limit)
      end
    end

    override :supports_saved_replies?
    def supports_saved_replies?
      licensed_feature_available?(:group_saved_replies)
    end

    # Availability of the group "Secure" settings section (page + sidebar link).
    def secure_settings_available?
      dependency_firewall_setting_available? ||
        ::SecretsManagement::Availability.namespace_configurable?(self) ||
        ai_governance_setting_available?
    end

    # Not limited to root groups, because subgroups can override the inherited value.
    def ai_governance_setting_available? # rubocop:disable Gitlab/OmniscientClassMethods -- Kept beside the other Secure settings availability checks that secure_settings_available? combines.
      ::Feature.enabled?(:ai_governance_settings_page, root_ancestor, type: :wip)
    end

    def dependency_firewall_setting_available?
      ::Security::DependencyFirewall::Availability.namespace_configurable?(self)
    end

    def licensed_ai_features_available?
      licensed_feature_available?(:ai_features) ||
        licensed_feature_available?(:ai_chat) ||
        root_ancestor.has_active_gitlab_credits_add_on?
    end

    def policy_store_experiment_available?
      ::Gitlab::CurrentSettings.policy_store_experiment_enabled? &&
        ::Feature.enabled?(:security_policies_v2, root_ancestor) &&
        ::Security::PolicyAvailability.available?(self, :security_orchestration_policies)
    end

    def policy_store_experiment_active?
      policy_store_experiment_available? && root_ancestor.policy_store_experiment_enabled?
    end

    def licensed_duo_core_features_available?
      licensed_feature_available?(:code_suggestions) || licensed_feature_available?(:ai_chat)
    end

    def duo_sast_fp_detection_enabled?
      ::ProjectSetting.with_duo_sast_fp_detection_enabled.joins(:project).merge(all_projects).exists?
    end

    def duo_sast_vr_workflow_enabled?
      ::ProjectSetting.with_duo_sast_vr_workflow_enabled.joins(:project).merge(all_projects).exists?
    end

    def allow_group_items_in_project_autocompletion?
      ::Feature.enabled?(:allow_group_items_in_project_autocompletion, self, type: :gitlab_com_derisk) &&
        licensed_feature_available?(:epics)
    end

    def ai_review_merge_request_allowed?(user)
      ::Gitlab::Duo::CodeReview.enabled?(user: user, container: self)
    end

    def project_epics_enabled?
      licensed_feature_available?(:epics) &&
        feature_flag_enabled_for_self_or_ancestor?(:project_work_item_epics, type: :beta)
    end

    class_methods do
      def groups_user_can(groups, user, action, same_root: false)
        # If :use_traversal_ids is enabled we can use filter optmization
        # to skip some permission check queries in group descendants.
        if same_root && can_use_epics_filtering_optimization?(groups, action)
          filter_groups_user_can(groups: groups, user: user, action: action)
        else
          groups = ::Gitlab::GroupPlansPreloader.new.preload(groups)

          # if we are sure that all groups have the same root group, we can
          # preset root_ancestor for all of them to avoid an additional SQL query
          # done for each group permission check:
          # https://gitlab.com/gitlab-org/gitlab/issues/11539
          preset_root_ancestor_for(groups) if same_root

          super
        end
      end

      def can_use_epics_filtering_optimization?(groups, action)
        return false unless ALLOWED_ACTIONS_TO_USE_FILTERING_OPTIMIZATION.include?(action)

        return false unless groups.any?

        groups.first.use_traversal_ids?
      end

      # Manually preloads saml_providers, which cannot be done in AR, since the
      # relationship is on the root ancestor.
      # This is required since the `:read_group` ability depends on `Group.saml_provider`
      def preload_root_saml_providers(groups)
        saml_providers = SamlProvider.where(group: groups.map(&:root_ancestor).uniq).index_by(&:group_id)

        return unless saml_providers

        groups.each do |group|
          group.root_saml_provider = saml_providers[group.root_ancestor.id]
        end
      end

      def with_api_scopes
        super()
          .preload(
            :ldap_group_links,
            :saml_group_links,
            namespace_template_setting: :file_template_project,
            group_wiki_repository: :shard)
      end

      private

      # Used when all groups that user is fetching epics (or work item epics) for belongs to the same hierarchy.
      # It prevents doing one query to check user access for each group which causes
      # timeouts on big hierarchies.
      # Instead of iterating over all groups over policies we perform a union of queries
      # to get all groups that users can read epics / work item epics with:
      #
      #  1 fragment takes all groups via direct authorization
      #  1 fragment to take groups authorized by shares
      #  1 to get groups authorized via project membership
      #  1 to get public/internal groups within the hierarchy
      #
      # More information at https://gitlab.com/gitlab-org/gitlab/-/issues/367868#note_1027151497
      def filter_groups_user_can(groups:, user:, action:)
        top_level_group = groups.first&.root_ancestor

        return ::Group.none unless top_level_group
        return ::Group.none unless top_level_group.feature_available?(:epics)

        access_level =
          if [:read_confidential_epic, :read_confidential_issues].include?(action)
            ::Gitlab::Access::PLANNER
          else
            ::Gitlab::Access::GUEST
          end

        # Looked up once: each call runs a pg_catalog query.
        traversal_ids_type = ::Namespace.traversal_ids_type

        queries_for_union = [
          hierarchy_group_ids_authorized_by_membership(user, top_level_group, access_level, traversal_ids_type),
          hierarchy_group_ids_authorized_by_share(user, groups, access_level, traversal_ids_type)
        ]

        if [:read_epic, :read_work_item].include?(action)
          queries_for_union << hierarchy_groups_authorized_by_project_membership(user, top_level_group)

          # Gets public and internal groups
          # Not needed if top level group is private
          queries_for_union << top_level_group.self_and_descendants.not_private.select(:id) unless top_level_group.private?
        end

        group_ids_union = ::Gitlab::SQL::Union.new(queries_for_union)

        where(id: groups.select(:id)).where("id IN (#{group_ids_union.to_sql})") # rubocop:disable GitlabSecurity/SqlInjection
      end

      def hierarchy_group_ids_authorized_by_membership(user, hierarchy_parent, access_level, traversal_ids_type)
        where("traversal_ids && ARRAY(?)::#{traversal_ids_type}",
          hierarchy_parent.members_with_descendants
            .where('access_level >= ?', access_level)
            .where(user: user)
            .select(:source_id)
        ).select(:id)
      end

      def hierarchy_group_ids_authorized_by_share(user, groups_hierarchy, access_level, traversal_ids_type)
        where("traversal_ids && ARRAY(?)::#{traversal_ids_type}",
          ::GroupGroupLink
            .where(shared_group_id: groups_hierarchy.select(:id))
            .where('group_access >= ?', access_level)
            .where(shared_with_group_id: ::GroupMember.where(user: user).authorizable.select(:source_id))
            .select(:shared_group_id)
        ).select(:id)
      end

      def hierarchy_groups_authorized_by_project_membership(user, hierarchy_parent)
        group_ids_that_has_projects =
          ::Project.for_group_and_its_subgroups(hierarchy_parent)
            .public_or_visible_to_user(user).select(:namespace_id)

        where(id: group_ids_that_has_projects).select('unnest(traversal_ids)')
      end
    end

    attr_writer :root_saml_provider

    def root_saml_provider
      strong_memoize(:root_saml_provider) { root_ancestor.saml_provider }
    end

    def ip_restriction_ranges
      return unless ip_restrictions.present?

      ip_restrictions.map(&:range).join(",")
    end

    def allowed_email_domains_list
      return if allowed_email_domains.empty?

      allowed_email_domains.domain_names.join(",")
    end

    def human_ldap_access
      ::Gitlab::Access.options_with_owner.key(ldap_access)
    end

    # NOTE: Backwards compatibility with old ldap situation
    def ldap_cn
      ldap_group_links.first.try(:cn)
    end

    def ldap_access
      ldap_group_links.first.try(:group_access)
    end

    override :ldap_synced?
    def ldap_synced?
      (::Gitlab.config.ldap.enabled && ldap_group_links.any?(&:active?)) || super
    end

    def mark_ldap_sync_as_failed(error_message, skip_validation: false)
      return false unless ldap_sync_started?

      error_message = ::Gitlab::UrlSanitizer.sanitize(error_message)

      if skip_validation
        # A group that does not validate cannot transition out of its
        # current state, so manually set the ldap_sync_status
        update_columns(ldap_sync_error: error_message, ldap_sync_status: 'failed')
      else
        fail_ldap_sync
        update_column(:ldap_sync_error, error_message)
      end
    end

    # This token conveys that the anonymous user is allowed to know of the group
    # Used to avoid revealing that a group exists on a given path
    def saml_discovery_token
      ensure_saml_discovery_token!
    end

    def saml_enabled?
      group_saml_enabled? || global_saml_enabled?
    end

    def saml_group_sync_available?
      feature_available?(:saml_group_sync) && root_ancestor.saml_enabled?
    end

    # Groups enforce the membership lock through GroupPolicy, so membership_locked? is false and no group is
    # locked here. Defined so any member source can be asked; a future group lock then denies by default.
    def membership_locked_for?(_actor, service_account:) # rubocop:disable Lint/UnusedMethodArgument, Gitlab/OmniscientClassMethods -- Same signature as Project#membership_locked_for?; security fix, kept beside membership_lock.
      membership_locked?
    end

    # Whether the instance-wide LDAP/SAML membership lock applies to this group. Mirrors the GroupPolicy
    # lock rules: the SAML lock needs SAML group sync to be available (licensed and SAML configured).
    def instance_membership_lock_applies? # rubocop:disable Gitlab/OmniscientClassMethods -- Security fix, kept beside membership_lock.
      return true if ::Gitlab::CurrentSettings.lock_memberships_to_ldap?

      ::Gitlab::CurrentSettings.lock_memberships_to_saml? && saml_group_sync_available?
    end

    def group_saml_enabled?
      return false unless saml_provider && ::Gitlab::Auth::GroupSaml::Config.enabled?

      saml_provider.persisted? && saml_provider.enabled?
    end

    def global_saml_enabled?
      ::Gitlab::Auth::Saml::Config.enabled?
    end

    def jira_issues_integration_available?
      feature_available?(:jira_issues_integration)
    end

    def multiple_approval_rules_available?
      feature_available?(:multiple_approval_rules)
    end

    override :multiple_issue_boards_available?
    def multiple_issue_boards_available?
      feature_available?(:multiple_group_issue_boards)
    end

    def group_project_template_available?
      feature_available?(:group_project_templates)
    end

    def scoped_variables_available?
      feature_available?(:group_scoped_ci_variables)
    end

    def first_non_empty_project
      all_children_projects = self.projects_for_group_and_its_subgroups_without_deleted
      all_children_projects.detect { |project| !project.empty_repo? }
    end

    def root_ancestor_ip_restrictions
      return ip_restrictions if parent_id.nil?

      root_ancestor.ip_restrictions
    end

    def root_ancestor_allowed_email_domains
      return allowed_email_domains if parent_id.nil?

      root_ancestor.allowed_email_domains
    end

    def owner_of_email?(email)
      return false unless ValidateEmail.valid?(email)

      return false unless domain_verification_available?

      email_domain = Mail::Address.new(email).domain&.downcase
      return false unless email_domain

      all_projects_pages_domains(only_verified: true).find_by_domain_case_insensitive(email_domain).present?
    end

    # Overrides a method defined in `::EE::Namespace`
    # Reads from namespace_template_settings to match the preload path.
    override :checked_file_template_project
    def checked_file_template_project
      project = namespace_template_setting&.file_template_project

      return unless project && (
          project_ids.include?(project.id) || shared_project_ids.include?(project.id))

      # The license check would normally be the cheapest to perform, so would
      # come first. In this case, the method is carefully designed to perform
      # no SQL at all, but `feature_available?` will cause an ApplicationSetting
      # to be created if it doesn't already exist! This is mostly a problem in
      # the specs, but best avoided in any case.
      return unless feature_available?(:custom_file_templates_for_namespace)

      project
    end

    override :block_seat_overages?
    def block_seat_overages?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
        namespace_settings.seat_control_block_overages?
    end

    def seat_overage?
      return false unless gitlab_subscription

      members_count = billable_members_count_with_reactive_cache

      return false unless members_count

      gitlab_subscription.seats < members_count
    end

    def calculate_reactive_cache
      billable_members_count
    end

    def billable_members_count_with_reactive_cache
      with_reactive_cache do |return_value|
        return_value
      end
    end

    override :supports_events?
    def supports_events?
      feature_available?(:epics)
    end

    def vulnerabilities
      ::Vulnerability.where(id: Vulnerabilities::Read.by_group(self).select(:vulnerability_id).unarchived)
    end

    def vulnerability_reads
      ::Vulnerabilities::Read.by_group(self)
    end

    def next_traversal_ids
      traversal_ids.dup.tap { |ids| ids[-1] += 1 }
    end

    def vulnerability_scanners
      ::Vulnerabilities::Scanner.where(project: Vulnerabilities::Statistic.by_group(self).unarchived.select(:project_id))
    end

    def vulnerability_historical_statistics
      ::Vulnerabilities::NamespaceHistoricalStatistic.for_namespace_and_descendants(self)
    end

    def vulnerability_namespace_statistic
      super || build_vulnerability_namespace_statistic
    end

    def predefined_push_rule
      strong_memoize(:predefined_push_rule) do
        next group_push_rule if group_push_rule

        if has_parent?
          parent.predefined_push_rule
        else
          OrganizationPushRuleFinder.new(organization).execute
        end
      end
    end

    def owners_emails
      self.pluck_member_user(:email, filters: { access_level: ::GroupMember::OWNER })
    end

    # this method will be delegated to namespace_settings, but as we need to wait till
    # all groups will have namespace_settings created via background migration,
    # we need to serve it from this class
    def prevent_forking_outside_group?
      return namespace_settings.prevent_forking_outside_group? if namespace_settings

      root_ancestor.saml_provider&.prohibited_outer_forks?
    end

    def service_access_tokens_expiration_enforced?
      namespace_settings.service_access_tokens_expiration_enforced if namespace_settings
    end

    def minimal_access_role_allowed?
      feature_available?(:minimal_access_role) && !has_parent?
    end

    override :member?
    def member?(user, min_access_level = minimal_member_access_level)
      return false unless user

      return super unless min_access_level == ::Gitlab::Access::MINIMAL_ACCESS
      return super unless minimal_access_role_allowed?

      ::Members::MembersWithParents
        .new(self)
        .members(minimal_access: true)
        .find_by(user_id: user.id)
        .present?
    end

    def minimal_member_access_level
      minimal_access_role_allowed? ? ::Gitlab::Access::MINIMAL_ACCESS : ::Gitlab::Access::GUEST
    end

    def members_with_descendants_including_minimal_access
      ::GroupMember
        .left_join_users
        .where(users: { state: 'active' })
        .without_invites_and_requests(minimal_access: true)
        .reorder(nil)
        .where(source_id: self_and_descendants.without_order.select(:id))
    end

    override :access_level_roles
    def access_level_roles
      levels = ::GroupMember.access_level_roles
      return levels unless minimal_access_role_allowed?

      levels.merge(::Gitlab::Access::MINIMAL_ACCESS_HASH)
    end

    override :roles_user_can_assign
    def roles_user_can_assign(current_user, roles = access_level_roles)
      super(current_user, roles)
    end

    override :users_count
    def users_count
      return all_group_members.count if minimal_access_role_allowed?

      members.count
    end

    def releases_count
      ::Release.by_namespace_id(self_and_descendants.select(:id)).count
    end

    def releases_percentage
      calculate_sql = <<~SQL
        (
          COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM releases WHERE releases.project_id = projects.id)) * 100.0 / GREATEST(COUNT(*), 1)
        )::integer AS releases_percentage
      SQL

      self.class.count_by_sql(
        ::Project.select(calculate_sql)
        .where(namespace_id: self_and_descendants.select(:id)).to_sql
      )
    end

    override :execute_hooks
    def execute_hooks(data, hooks_scope)
      super

      return unless feature_available?(:group_webhooks)

      # By default the webhook resource_access_token_hooks will execute for
      # seven_days interval but we have a setting to allow webhook execution
      # for thirty_days and sixty_days_plus interval too.
      is_extended_expiry_webhook = hooks_scope == :resource_access_token_hooks &&
        data[:interval] != :seven_days

      group_hooks = if is_extended_expiry_webhook
                      GroupHook.where(group_id: groups_for_extended_webhook_execution_on_token_expiry)
                    else
                      GroupHook.where(group_id: self_and_ancestors)
                    end

      execute_async_hooks(group_hooks, hooks_scope, data)
    end

    override :has_active_hooks?
    def has_active_hooks?(hooks_scope = :push_hooks)
      strong_memoize_with(:has_active_hooks, hooks_scope) do
        feature_available?(:group_webhooks) &&
          GroupHook.where(group_id: self_and_ancestors).hooks_for(hooks_scope).any?
      end
    end

    override :git_transfer_in_progress?
    def git_transfer_in_progress?
      reference_counter(type: ::Gitlab::GlRepository::WIKI).value > 0
    end

    def repository_storage
      group_wiki_repository&.shard_name || ::Repository.pick_storage_shard
    end

    def user_cap_reached?(use_cache: false)
      return false unless user_cap_available?

      return false unless root_ancestor.namespace_settings&.seat_control_user_cap?

      user_cap = root_ancestor.namespace_settings&.new_user_signups_cap
      return false unless user_cap

      members_count = use_cache ? root_ancestor.billable_members_count_with_reactive_cache : root_ancestor.billable_members_count
      return false unless members_count

      user_cap <= members_count
    end

    def shared_externally?
      strong_memoize(:shared_externally) do
        internal_groups = self.self_and_descendants

        group_links = self.class.invited_groups_in_groups_for_hierarchy(self)
                          .where.not(group_group_links: { shared_with_group_id: internal_groups })
                          .exists?

        project_links = self.class.invited_groups_in_projects_for_hierarchy(self)
                            .where.not(project_group_links: { group_id: internal_groups })
                            .exists?

        group_links || project_links
      end
    end

    def has_free_or_no_subscription?
      # this is a side-effect free version of checking if a namespace
      # is on a free plan or has no plan - see https://gitlab.com/gitlab-org/gitlab/-/merge_requests/80839#note_851566461
      strong_memoize(:has_free_or_no_subscription) do
        subscription = root_ancestor.gitlab_subscription

        # there is a chance that subscriptions do not have a plan https://gitlab.com/gitlab-org/gitlab/-/merge_requests/81432#note_858514873
        if subscription&.plan_name
          subscription.plan_name == ::GitlabSubscriptions::SystemDefined::Plan::FREE
        else
          true
        end
      end
    end

    override :capacity_left_for_user?
    def capacity_left_for_user?(user)
      return true unless user_cap_available?
      return true if user_exempt_from_cap?(user)

      !user_cap_reached?
    end

    def enforce_free_user_cap?
      ::Namespaces::FreeUserCap::Enforcement.new(self).enforce_cap?
    end

    # Members belonging directly to Group or its subgroups

    # Checks if user belongs to billed_group_users
    def billed_group_user?(user, exclude_guests: false)
      billed_group_users(exclude_guests: exclude_guests).exists?(id: user.id)
    end

    # Checks if user belongs to billed_project_users
    def billed_project_user?(user, exclude_guests: false)
      billed_project_users(exclude_guests: exclude_guests).exists?(id: user.id)
    end

    # Checks if user belongs to billed_shared_group_users
    def billed_shared_group_user?(user, exclude_guests: false)
      billed_shared_group_users(exclude_guests: exclude_guests).exists?(id: user.id)
    end

    # Checks if user belongs to billed_invited_group_to_project_users
    def billed_shared_project_user?(user, exclude_guests: false)
      billed_invited_group_to_project_users(exclude_guests: exclude_guests).exists?(id: user.id)
    end

    def eligible_for_gitlab_duo_pro_seat?(user)
      billed_group_user?(user) ||
        billed_project_user?(user) ||
        billed_shared_group_user?(user) ||
        billed_shared_project_user?(user)
    end

    def gitlab_duo_eligible_user_ids
      # all billable users and guests are eligible to be assigned gitlab duo
      billed_user_ids_including_guests[:user_ids]
    end

    def duo_settings_path
      if ::GitlabSubscriptions::SubscriptionHelper.gitlab_com_subscription? && root?
        ::Gitlab::Routing.url_helpers.group_settings_gitlab_duo_configuration_index_path(self)
      else
        ::Gitlab::Routing.url_helpers.edit_group_path(self, anchor: 'js-gitlab-duo-settings')
      end
    end

    def parent_epic_ids_in_ancestor_groups
      ids = Set.new
      epics.has_parent.each_batch(of: EPIC_BATCH_SIZE, column: :iid) do |batch|
        ids += ::Epic.id_in(batch.select(:parent_id)).where.not(group_id: id).limit(EPIC_BATCH_SIZE).pluck(:id)
      end

      ids.to_a
    end

    def code_owner_approval_required_available?
      feature_available?(:code_owner_approval_required)
    end

    def has_dependencies?
      sbom_occurrences.exists?
    end

    def sbom_occurrences
      Sbom::Occurrence.for_namespace_and_descendants(self).unarchived
    end

    override :reached_project_access_token_limit?
    def reached_project_access_token_limit?
      actual_limits.exceeded?(:project_access_token_limit, active_project_tokens_of_root_ancestor)
    end

    def count_within_namespaces
      ::Group.where("traversal_ids @> '{?}'", id).count
    end

    def can_manage_extensions_marketplace_for_enterprise_users?
      root? &&
        licensed_feature_available?(:disable_extensions_marketplace_for_enterprise_users) &&
        ::WebIde::ExtensionMarketplace.feature_enabled_from_application_settings?
    end

    def enterprise_users_extensions_marketplace_enabled?
      return true unless can_manage_extensions_marketplace_for_enterprise_users?

      namespace_settings.enterprise_users_extensions_marketplace_enabled?
    end

    def disable_personal_access_tokens_available?
      root? &&
        ::Gitlab::Saas.feature_available?(:disable_personal_access_tokens) &&
        licensed_feature_available?(:disable_personal_access_tokens)
    end

    # Disable personal access tokens for enterprise users of this group
    def disable_personal_access_tokens?
      disable_personal_access_tokens_available? &&
        namespace_settings.disable_personal_access_tokens?
    end

    def allow_personal_snippets_available?(user = nil)
      root? &&
        enterprise_user_settings_available?(user) &&
        ::Gitlab::Saas.feature_available?(:allow_personal_snippets) &&
        licensed_feature_available?(:allow_personal_snippets)
    end

    def can_configure_enterprise_user_account_deletion?(user = nil)
      enterprise_user_settings_available?(user) &&
        prevent_enterprise_user_account_deletion_licensed?
    end

    def prevent_enterprise_user_account_deletion?
      return false unless domain_verification_available?
      return false unless prevent_enterprise_user_account_deletion_licensed?

      !namespace_settings.allow_enterprise_user_account_deletion?
    end

    def disallow_personal_snippets?
      root? &&
        ::Gitlab::Saas.feature_available?(:allow_personal_snippets) &&
        licensed_feature_available?(:allow_personal_snippets) &&
        !namespace_settings.allow_personal_snippets?
    end

    def disable_ssh_keys_available?
      root? &&
        ::Gitlab::Saas.feature_available?(:disable_ssh_keys) &&
        licensed_feature_available?(:disable_ssh_keys)
    end

    # Disable SSH Keys for enterprise users of this group
    def disable_ssh_keys?
      disable_ssh_keys_available? &&
        namespace_settings.disable_ssh_keys?
    end

    override :use_elasticsearch?
    def use_elasticsearch?
      return ::Gitlab::CurrentSettings.elasticsearch_indexes_namespace?(self) if ::Gitlab::CurrentSettings.elasticsearch_limit_indexing?

      ::Gitlab::CurrentSettings.elasticsearch_indexing?
    end

    def extended_grat_expiry_webhooks_execute?
      licensed_feature_available?(:group_webhooks) &&
        namespace_settings&.extended_grat_expiry_webhooks_execute?
    end

    def gitlab_credits_entitled?
      licensed_feature_available?(:group_usage_billing) ||
        has_active_add_on_purchase?(:gitlab_credits)
    end

    def active_compliance_frameworks?
      # test default framework first since it is most likely to have projects assigned
      [[default_compliance_framework] + compliance_management_frameworks].flatten.compact.uniq.any? do |framework|
        framework.projects.any?
      end
    end

    def groups_for_extended_webhook_execution_on_token_expiry
      self_and_ancestors
        .joins(:namespace_settings)
        .where(namespace_settings: { extended_grat_expiry_webhooks_execute: true })
    end

    def enterprise_user_settings_available?(user = nil)
      root? &&
        domain_verification_available? &&
        Ability.allowed?(user, :read_enterprise_user, self)
    end

    def built_in_project_templates_enabled_available?
      licensed_feature_available?(:built_in_project_templates_enabled)
    end

    def allow_built_in_project_templates?
      return true unless built_in_project_templates_enabled_available?

      built_in_project_templates_enabled
    end

    def virtual_registry_policy_subject
      ::VirtualRegistries::Policies::Group.new(self)
    end

    def es_parent
      "group_#{root_ancestor.id}"
    end

    def elastic_reference
      ::Search::Elastic::References::Group.serialize(self)
    end

    # Set by the private before_destroy callback below. Never computes -
    # reading it before destroy runs, or after a destroy that rolled
    # back, returns an empty array instead of caching a stale answer
    # against state that has since changed.
    def reassigned_protected_environment_approval_rules
      @reassigned_protected_environment_approval_rules || [] # rubocop:disable Gitlab/ModuleWithInstanceVariables
    end

    private

    # Bots do not take up a billable seat.
    def user_exempt_from_cap?(user)
      return false if user.blank?

      user.bot? || ::Member.in_hierarchy(root_ancestor).with_user(user).with_state(:active).exists?
    end

    def reassign_protected_environment_approval_rules
      @reassigned_protected_environment_approval_rules = ::ProtectedEnvironment.reassign_sole_group_approver(self) # rubocop:disable Gitlab/ModuleWithInstanceVariables
    end

    def prevent_enterprise_user_account_deletion_licensed?
      ::Gitlab::Saas.feature_available?(:prevent_enterprise_user_account_deletion) &&
        licensed_feature_available?(:prevent_enterprise_user_account_deletion)
    end

    def execute_async_hooks(group_hooks, hooks_scope, data)
      group_hooks.hooks_for(hooks_scope).each do |hook|
        hook.async_execute(data, hooks_scope.to_s)
      end
    end

    def active_project_tokens_of_root_ancestor
      root_ancestor_and_descendants_project_bots = ::User
        .joins(projects: :group)
        .where(namespaces: { id: root_ancestor.self_and_descendants.select(:id) })
        .project_bot
        .allow_cross_joins_across_databases(url: "https://gitlab.com/gitlab-org/gitlab/-/issues/428542")

      ::PersonalAccessToken.active.joins(:user).merge(root_ancestor_and_descendants_project_bots)
    end

    override :post_create_hook
    def post_create_hook
      super

      execute_subgroup_hooks(:create)
    end

    override :post_destroy_hook
    def post_destroy_hook
      super

      execute_subgroup_hooks(:destroy)
    end

    def clear_file_template_project_id
      setting = namespace_template_setting
      return unless setting&.file_template_project_id
      return if checked_file_template_project_id.present?

      setting.file_template_project_id = nil
    end

    def execute_subgroup_hooks(event)
      return unless subgroup?
      return unless parent&.has_active_hooks?(:subgroup_hooks)

      run_after_commit do
        data = ::Gitlab::HookData::SubgroupBuilder.new(self).build(event)
        # Imagine a case where a subgroup has a webhook with `subgroup_events` enabled.
        # When this subgroup is removed, there is no point in this subgroup's webhook itself being notified
        # that `self` was removed. Rather, we should only care about notifying its ancestors
        # and hence we need to trigger the hooks starting only from its `parent` group.
        parent&.execute_hooks(data, :subgroup_hooks) # remove safe navigation with https://gitlab.com/gitlab-org/gitlab/-/issues/508611
      end
    end

    def members_with_elevating_guest_member_role(groups)
      ::GroupMember.active_without_invites_and_requests
        .with_source_id(groups.self_and_ancestors)
        .merge(::GroupMember.elevated_guests)
    end

    def users_without_bots(members, merge_condition: ::User.all)
      ::User.id_in(members.select(:user_id)).without_bots.merge(merge_condition)
            .allow_cross_joins_across_databases(url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/417464')
    end

    def projects_for_group_and_its_subgroups_without_deleted
      ::Project.for_group_and_its_subgroups(self).non_archived.without_deleted
    end

    override :safe_read_repository_read_only_column
    def safe_read_repository_read_only_column
      ::NamespaceSetting.where(namespace: self).pick(:repository_read_only)
    end

    override :update_repository_read_only_column
    def update_repository_read_only_column(value)
      settings = namespace_settings || create_namespace_settings

      settings.update_column(:repository_read_only, value)
    end
  end
end
