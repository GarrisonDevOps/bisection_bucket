# frozen_string_literal: true

module EE
  module NamespaceSetting
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    DUO_AVAILABILITY_VALUES = %w[always_on default_on default_off never_on].freeze

    prepended do
      include ::Ai::CodeReview::DepthSettings

      after_update_commit :maintain_elasticsearch_group_active_state, if: :archived_previously_changed?

      DORMANT_REVIEW_PERIOD = 18.hours

      cascading_attr :duo_features_enabled, :model_prompt_cache_enabled, :auto_duo_code_review_enabled,
        :duo_code_review_decisions_enabled, :duo_code_review_approval_counts_enabled,
        :duo_remote_flows_enabled, :duo_foundational_flows_enabled, :duo_scheduled_triggers_enabled,
        :built_in_project_templates_enabled,
        :tool_approval_for_session_enabled, :duo_custom_agents_enabled, :duo_custom_flows_enabled,
        :duo_external_agents_enabled, :ai_audit_events_storage_enabled,
        :auto_duo_code_review_on_push_enabled, :duo_auto_mode_enabled, :ai_governance_enabled,
        :ai_agent_governance_enforcement

      scope :requiring_dormant_member_review, ->(limit) do
        # look for settings that have not been reviewed in more than
        # 18 hours (catering for 6-hourly review schedule)
        where(remove_dormant_members: true)
          .where('last_dormant_member_review_at < ? OR last_dormant_member_review_at IS NULL',
            DORMANT_REVIEW_PERIOD.ago)
          .limit(limit)
      end
      scope :duo_features_set, ->(setting) { where(duo_features_enabled: setting) }
      scope :order_by_last_dormant_member_review_asc, -> do
        order("last_dormant_member_review_at ASC NULLS FIRST")
      end

      attribute :enabled_foundational_flows, :string, array: true, default: nil

      belongs_to :default_compliance_framework, optional: true, class_name: "ComplianceManagement::Framework"

      validates :unique_project_download_limit,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 10_000 },
        presence: true
      validates :unique_project_download_limit_interval_in_seconds,
        numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 10.days.to_i },
        presence: true
      validates :unique_project_download_limit_allowlist,
        length: { maximum: 100, message: ->(object, data) { _("exceeds maximum length (100 usernames)") } },
        allow_nil: false,
        user_existence: true,
        if: :unique_project_download_limit_allowlist_changed?
      validates :unique_project_download_limit_alertlist,
        length: { maximum: 100, message: ->(object, data) { _("exceeds maximum length (100 user ids)") } },
        allow_nil: false,
        user_id_existence: true,
        if: :unique_project_download_limit_alertlist_changed?
      validates :ai_agent_governance_enforcement,
        numericality: { only_integer: true },
        inclusion: { in: ::Ai::Governance::AgentCredentialEnforcement::MODES.values },
        allow_nil: true,
        if: :will_save_change_to_ai_agent_governance_enforcement?
      validates :ai_agent_governance_enforcement, 'ai/governance/enforcement_mode_input': true,
        if: :will_save_change_to_ai_agent_governance_enforcement?
      validates :ai_agent_governance_enforcement, presence: true,
        if: -> {
          will_save_change_to_ai_agent_governance_enforcement? && !ai_agent_governance_enforcement_in_database.nil?
        }

      alias_attribute :duo_core_features_enabled, :duo_nano_features_enabled

      with_options if: :will_save_change_to_duo_core_features_enabled? do
        validates :duo_core_features_enabled, inclusion: { in: [true, false] }
        validate :valid_namespace_for_duo_core_features
      end

      validates :new_user_signups_cap,
        numericality: { only_integer: true, greater_than_or_equal_to: 0 },
        if: -> { seat_control_user_cap? }

      validate :user_cap_allowed, if: -> { enabling_user_cap? }
      validate :experiment_features_allowed
      validates :remove_dormant_members, inclusion: { in: [false] }, if: :subgroup?
      validates :remove_dormant_members_period,
        numericality: { only_integer: true, greater_than_or_equal_to: 90, less_than_or_equal_to: 1827 } # 90d - ~5 years
      validates :allow_enterprise_bypass_placeholder_confirmation, inclusion: { in: [true, false] }

      enum :enterprise_users_extensions_marketplace_opt_in_status,
        ::Enums::WebIde::ExtensionsMarketplaceOptInStatus.statuses, prefix: :enterprise_users_extensions_marketplace

      attribute :security_policies, default: -> { {} }
      validates :security_policies, json_schema: { filename: "application_setting_security_policies" }

      validates :pipeline_execution_policies_per_configuration_limit,
        numericality: {
          only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20, allow_nil: true
        }
      validates :scan_execution_policies_per_configuration_limit,
        numericality: {
          only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20, allow_nil: true
        }
      validates :approval_policies_per_configuration_limit,
        numericality: {
          only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20, allow_nil: true
        }
      validates :vulnerability_management_policies_per_configuration_limit,
        numericality: {
          only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 20, allow_nil: true
        }

      with_options(inclusion: { in: [true, false], message: N_('must be a boolean value') }) do
        validates(
          :experiment_features_enabled,
          :display_gitlab_credits_user_data,
          :dependency_firewall_enabled
        )
      end

      jsonb_accessor :enterprise_user_settings,
        allow_enterprise_user_account_deletion: [:boolean, { default: true }],
        allow_non_enterprise_placeholder_reassignment: [:boolean, { default: false }]

      validates :enterprise_user_settings,
        json_schema: { filename: "namespace_setting_enterprise_user_settings" }

      jsonb_accessor :usage_billing,
        display_gitlab_credits_user_data: [:boolean, { default: true }]

      validates :usage_billing, json_schema: { filename: "usage_billing_settings" }

      jsonb_accessor :security_policies, pipeline_execution_policies_per_configuration_limit: [:integer, { default: 0 }]
      jsonb_accessor :security_policies, scan_execution_policies_per_configuration_limit: [:integer, { default: 0 }]
      jsonb_accessor :security_policies, approval_policies_per_configuration_limit: [:integer, { default: 0 }]
      jsonb_accessor :security_policies,
        vulnerability_management_policies_per_configuration_limit: [:integer, { default: 0 }]
      jsonb_accessor :security_policies,
        dependency_firewall_policies_per_configuration_limit: [:integer, { default: 0 }]

      before_save :clear_new_user_signups_cap, unless: -> { seat_control_user_cap? }
      before_save :set_prevent_sharing_groups_outside_hierarchy
      before_save :mark_duo_code_review_by_default_as_disabled

      after_commit :trigger_todo_creation, on: :update, if: :saved_change_to_duo_core_features_enabled?
      after_commit :track_restricted_access_disabled, on: :update, if: :restricted_access_disabled?
      after_commit :track_restricted_access_enabled, on: :update, if: :restricted_access_enabled?

      delegate :root_ancestor, to: :namespace

      def enterprise_users_extensions_marketplace_enabled=(value)
        status = ActiveRecord::Type::Boolean.new.cast(value) ? 'enabled' : 'disabled'

        self.enterprise_users_extensions_marketplace_opt_in_status = status
      end

      def prevent_forking_outside_group?
        saml_setting = root_ancestor.saml_provider&.prohibited_outer_forks?

        return saml_setting unless namespace.feature_available?(:group_forking_protection)

        saml_setting || root_ancestor.namespace_settings&.prevent_forking_outside_group
      end

      # Define three instance methods:
      #
      # - [attribute]_of_parent_group         Returns the configuration value of the parent group
      # - [attribute]?(inherit_group_setting) Returns the final value after inheriting the parent group
      # - [attribute]_locked?                 Returns true if the value is inherited from the parent group
      def self.cascading_with_parent_namespace(attribute)
        define_method("#{attribute}_of_parent_group") do
          namespace&.parent&.namespace_settings&.public_send("#{attribute}?", inherit_group_setting: true)
        end

        define_method("#{attribute}?") do |inherit_group_setting: false|
          result = if inherit_group_setting
                     public_send(attribute.to_s) || public_send("#{attribute}_of_parent_group")
                   else
                     public_send(attribute.to_s)
                   end

          !!result
        end

        define_method("#{attribute}_locked?") do
          !!public_send("#{attribute}_of_parent_group")
        end
      end

      cascading_with_parent_namespace :only_allow_merge_if_pipeline_succeeds
      cascading_with_parent_namespace :allow_merge_on_skipped_pipeline
      cascading_with_parent_namespace :only_allow_merge_if_all_discussions_are_resolved
      cascading_with_parent_namespace :allow_merge_without_pipeline

      def unique_project_download_limit_alertlist
        self[:unique_project_download_limit_alertlist].presence || active_owner_ids
      end

      def experiment_settings_allowed?
        namespace.root?
      end

      def prompt_cache_settings_allowed?
        namespace.root?
      end

      def user_cap_enabled?
        seat_control_user_cap? && namespace.root?
      end

      def duo_remote_flows_availability
        duo_remote_flows_enabled
      end

      def duo_remote_flows_availability=(value)
        return if duo_remote_flows_enabled_locked?(include_self: false)

        self.duo_remote_flows_enabled = value
        self.lock_duo_remote_flows_enabled = !value
      end

      def duo_foundational_flows_availability
        duo_foundational_flows_enabled
      end

      def duo_foundational_flows_availability=(value)
        return if duo_foundational_flows_enabled_locked?(include_self: false)

        self.duo_foundational_flows_enabled = value
        self.lock_duo_foundational_flows_enabled = !value
      end

      def duo_scheduled_triggers_availability
        duo_scheduled_triggers_enabled
      end

      def duo_scheduled_triggers_availability=(value)
        return if duo_scheduled_triggers_enabled_locked?(include_self: false)

        self.duo_scheduled_triggers_enabled = value
        self.lock_duo_scheduled_triggers_enabled = !value
      end

      def duo_custom_agents_availability
        duo_custom_agents_enabled
      end

      def duo_custom_agents_availability=(value)
        return if duo_custom_agents_enabled_locked?(include_self: false)

        self.duo_custom_agents_enabled = value
        self.lock_duo_custom_agents_enabled = !value
      end

      def duo_custom_flows_availability
        duo_custom_flows_enabled
      end

      def duo_custom_flows_availability=(value)
        return if duo_custom_flows_enabled_locked?(include_self: false)

        self.duo_custom_flows_enabled = value
        self.lock_duo_custom_flows_enabled = !value
      end

      def duo_external_agents_availability
        duo_external_agents_enabled
      end

      def duo_external_agents_availability=(value)
        return if duo_external_agents_enabled_locked?(include_self: false)

        self.duo_external_agents_enabled = value
        self.lock_duo_external_agents_enabled = !value
      end

      def tool_approval_for_session_availability
        Ai::ToolApprovalHelper.to_session_availability(
          tool_approval_for_session_enabled,
          tool_approval_for_session_enabled_locked?(include_self: true)
        )
      end

      def tool_approval_for_session_availability=(value)
        return if tool_approval_for_session_enabled_locked?(include_self: false)

        self.tool_approval_for_session_enabled = Ai::ToolApprovalHelper.enabled_for_session_availability(value)
        self.lock_tool_approval_for_session_enabled = Ai::ToolApprovalHelper.locked_for_session_availability(value)
      end

      def duo_auto_mode_availability
        Ai::ToolApprovalHelper.to_session_availability(
          duo_auto_mode_enabled,
          duo_auto_mode_enabled_locked?(include_self: true)
        )
      end

      def duo_auto_mode_availability=(value)
        return if duo_auto_mode_enabled_locked?(include_self: false)

        self.duo_auto_mode_enabled = Ai::ToolApprovalHelper.enabled_for_session_availability(value)
        self.lock_duo_auto_mode_enabled = Ai::ToolApprovalHelper.locked_for_session_availability(value)
      end

      def duo_availability
        if duo_features_enabled && duo_features_enabled_locked?(include_self: true)
          :always_on
        elsif duo_features_enabled && !duo_features_enabled_locked?(include_self: true)
          :default_on
        elsif !duo_features_enabled && !duo_features_enabled_locked?(include_self: true)
          :default_off
        else
          :never_on
        end
      end

      def duo_availability=(value)
        return if duo_features_enabled_locked?(include_self: false)

        case value
        when "always_on"
          self.duo_features_enabled = true
          self.lock_duo_features_enabled = true
        when "default_on"
          self.duo_features_enabled = true
          self.lock_duo_features_enabled = false
        when "default_off"
          self.duo_features_enabled = false
          self.lock_duo_features_enabled = false
        else
          self.duo_features_enabled = false
          self.lock_duo_features_enabled = true
          self.experiment_features_enabled = false
        end
      end

      def restricted_access_disabled?
        saved_change_to_seat_control? && seat_control_off?
      end

      def restricted_access_enabled?
        saved_change_to_seat_control? && seat_control_block_overages?
      end

      private

      def track_restricted_access_disabled
        ::Gitlab::InternalEvents.track_event(
          'restricted_access_disabled',
          namespace: namespace,
          additional_properties: restricted_access_context_properties
        )
      end

      def track_restricted_access_enabled
        ::Gitlab::InternalEvents.track_event(
          'restricted_access_enabled',
          namespace: namespace,
          additional_properties: restricted_access_context_properties
        )
      end

      def restricted_access_context_properties
        {
          subscription_tier: namespace.gitlab_subscription&.plan_name,
          seat_count: namespace.gitlab_subscription&.seats
        }
      end

      def trigger_todo_creation
        return unless ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)
        return unless duo_core_features_enabled

        ::GitlabSubscriptions::GitlabCom::DuoCoreTodoNotificationWorker
          .perform_in(::GitlabSubscriptions::DuoCore::DELAY_TODO_NOTIFICATION, namespace_id)
      end

      def enabling_user_cap?
        return false unless persisted? && seat_control_changed?

        seat_control_user_cap?
      end

      def user_cap_allowed
        return if namespace.user_cap_available? && namespace.root? && !namespace.shared_externally?

        errors.add(:seat_control, _("cannot be set to user cap"))
      end

      def clear_new_user_signups_cap
        self.new_user_signups_cap = nil
      end

      def set_prevent_sharing_groups_outside_hierarchy
        return unless user_cap_enabled? || namespace.block_seat_overages?

        self.prevent_sharing_groups_outside_hierarchy = true
      end

      def mark_duo_code_review_by_default_as_disabled
        return if enable_duo_code_review_by_default_disabled?
        return unless will_save_change_to_attribute?(:auto_duo_code_review_enabled, to: false)
        return unless namespace&.root?

        self.enable_duo_code_review_by_default = :disabled
      end

      def active_owner_ids
        return [] unless namespace&.group_namespace?

        namespace.non_invite_owner_members.where(user: ::User.active).distinct(:user_id).pluck_user_ids
      end

      def valid_namespace_for_duo_core_features
        return if namespace&.root? && namespace.group_namespace?

        errors.add(:duo_core_features_enabled, _('can only be set for root group namespace'))
      end

      def experiment_features_allowed
        return unless experiment_features_enabled_changed?
        return if experiment_settings_allowed?

        errors.add(:experiment_features_enabled, _("Experiment features' settings not allowed."))
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      EE_NAMESPACE_SETTINGS_PARAMS = %i[
        unique_project_download_limit
        unique_project_download_limit_interval_in_seconds
        unique_project_download_limit_allowlist
        unique_project_download_limit_alertlist
        auto_ban_user_on_excessive_projects_download
        default_compliance_framework_id
        only_allow_merge_if_pipeline_succeeds
        allow_merge_without_pipeline
        allow_merge_on_skipped_pipeline
        only_allow_merge_if_all_discussions_are_resolved
        experiment_features_enabled
        service_access_tokens_expiration_enforced
        duo_core_features_enabled
        duo_features_enabled
        lock_duo_features_enabled
        lock_duo_remote_flows_enabled
        auto_duo_code_review_enabled
        auto_duo_code_review_on_push_enabled
        lock_auto_duo_code_review_on_push_enabled
        duo_code_review_decisions_enabled
        duo_code_review_depth_allowed
        duo_code_review_default_depth
        duo_remote_flows_enabled
        duo_remote_flows_availability
        enterprise_users_extensions_marketplace_opt_in_status
        allow_enterprise_bypass_placeholder_confirmation
        allow_non_enterprise_placeholder_reassignment
        web_based_commit_signing_enabled
        lock_web_based_commit_signing_enabled
        ai_audit_events_storage_enabled
        lock_ai_audit_events_storage_enabled
        ai_governance_enabled
        lock_ai_governance_enabled
        ai_agent_governance_enforcement
        lock_ai_agent_governance_enforcement
        built_in_project_templates_enabled
        lock_built_in_project_templates_enabled
        duo_foundational_flows_enabled
        lock_duo_foundational_flows_enabled
        duo_foundational_flows_availability
        duo_scheduled_triggers_enabled
        lock_duo_scheduled_triggers_enabled
        duo_scheduled_triggers_availability
        enabled_foundational_flows
        allow_personal_snippets
        allow_enterprise_user_account_deletion
        tool_approval_for_session_enabled
        lock_tool_approval_for_session_enabled
        duo_custom_agents_enabled
        lock_duo_custom_agents_enabled
        duo_custom_agents_availability
        duo_custom_flows_enabled
        lock_duo_custom_flows_enabled
        duo_custom_flows_availability
        duo_external_agents_enabled
        lock_duo_external_agents_enabled
        duo_external_agents_availability
        policy_store_experiment_enabled
        dependency_firewall_enabled
        duo_auto_mode_enabled
        lock_duo_auto_mode_enabled
        duo_auto_mode_availability
      ].freeze

      def admin_locked_duo_features_for_ancestors_locked(namespace)
        where(namespace_id: namespace.self_and_ancestor_ids)
          .where(admin_locked_duo_features_enabled: true)
          .where.not(namespace_id: namespace.id)
          .includes(:namespace)
      end

      def admin_locked_duo_features_for_descendants_locked(namespace)
        where(namespace_id: namespace.self_and_descendant_ids)
          .where(admin_locked_duo_features_enabled: true)
          .where.not(namespace_id: namespace.id)
          .includes(:namespace)
      end

      override :allowed_namespace_settings_params
      def allowed_namespace_settings_params
        super + EE_NAMESPACE_SETTINGS_PARAMS
      end
    end

    def maintain_elasticsearch_group_active_state
      return unless namespace.group_namespace?

      ::Search::Elastic::GroupActiveStateWorker.perform_async(namespace_id)
    end

    # Descendants read a locked ancestor's stored column, so a locked namespace keeps
    # its explicit value instead of the cascade storing NULL when it matches the parent.
    def before_save_ai_agent_governance_enforcement
      return if lock_ai_agent_governance_enforcement?

      super
    end
    private :before_save_ai_agent_governance_enforcement
  end
end
