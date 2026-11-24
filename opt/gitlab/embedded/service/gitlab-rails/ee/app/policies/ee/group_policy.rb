# frozen_string_literal: true

module EE
  module GroupPolicy
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    # Run after the role checks: these conditions call CustomersDot, and with a
    # lower score DeclarativePolicy evaluates them even for non-members.
    SECRETS_MANAGER_ENTITLEMENT_SCORE = 64

    prepended do
      include ::Gitlab::Utils::StrongMemoize
      include RemoteDevelopment::GroupPolicy
      include Vulnerabilities::AdvancedVulnerabilityManagementPolicy
      include ::Sbom::AdvancedDependencyManagementPolicy
      include ::WorkItems::SharedPolicy
      include ::WorkItems::GroupPolicy
      include ::Ai::Catalog::McpServers::NamespacePolicy
      include ::Ai::DuoAgentPlatform::AccessPolicy

      condition(:ldap_synced, scope: :subject) { @subject.ldap_synced? }

      # Reads all of the user's maintainer project authorizations, so cheaper rules run first.
      condition(:has_maintainer_projects, score: 64) do
        group_projects_for(user: @user, group: @subject, min_access_level: ::ProjectMember::MAINTAINER).any?
      end

      condition(:epics_available, scope: :subject) { @subject.feature_available?(:epics) }
      condition(:iterations_available, scope: :subject) { @subject.feature_available?(:iterations) }
      condition(:subepics_available, scope: :subject) { @subject.feature_available?(:subepics) }
      condition(:custom_fields_available, scope: :subject) { @subject.feature_available?(:custom_fields) }
      condition(:external_audit_events_available, scope: :subject) do
        @subject.feature_available?(:external_audit_events)
      end
      condition(:contribution_analytics_available, scope: :subject) do
        @subject.feature_available?(:contribution_analytics)
      end

      condition(:group_analytics_dashboards_available, scope: :subject) do
        @subject.feature_available?(:group_level_analytics_dashboard)
      end

      condition(:cycle_analytics_available, scope: :subject) do
        @subject.feature_available?(:cycle_analytics_for_groups)
      end

      condition(:group_ci_cd_analytics_releases_available, scope: :subject) do
        @subject.licensed_feature_available?(:group_ci_cd_analytics_releases)
      end

      condition(:group_ci_cd_analytics_pipelines_available, scope: :subject) do
        ::Feature.enabled?(:group_ci_cd_analytics_pipelines_ff, @subject) &&
          @subject.licensed_feature_available?(:group_ci_cd_analytics_pipelines)
      end

      condition(:group_ci_cd_analytics_available) do
        group_ci_cd_analytics_pipelines_available? || group_ci_cd_analytics_releases_available?
      end

      condition(:group_repository_analytics_available, scope: :subject) do
        @subject.feature_available?(:group_repository_analytics)
      end

      condition(:group_coverage_reports_available, scope: :subject) do
        @subject.feature_available?(:group_coverage_reports)
      end

      condition(:group_activity_analytics_available, scope: :subject) do
        @subject.feature_available?(:group_activity_analytics)
      end

      condition(:group_devops_adoption_available, scope: :subject) do
        @subject.feature_available?(:group_level_devops_adoption)
      end

      condition(:group_credentials_inventory_available, scope: :subject) do
        ::Gitlab::Saas.feature_available?(:group_credentials_inventory) &&
          @subject.licensed_feature_available?(:credentials_inventory)
      end

      condition(:group_devops_adoption_enabled, scope: :global) do
        ::License.feature_available?(:group_level_devops_adoption)
      end

      condition(:dora4_analytics_available, scope: :subject) do
        @subject.feature_available?(:dora4_analytics)
      end

      condition(:group_membership_export_available, scope: :subject) do
        @subject.feature_available?(:export_user_permissions)
      end

      condition(:can_manage_ldap, scope: :user) do
        next true if can?(:admin_all_resources)

        ::Gitlab::CurrentSettings.allow_group_owners_to_manage_ldap?
      end

      condition(:memberships_locked_to_ldap, scope: :global) do
        ::Gitlab::CurrentSettings.lock_memberships_to_ldap?
      end

      condition(:memberships_locked_to_saml, scope: :global) do
        ::Gitlab::CurrentSettings.lock_memberships_to_saml
      end

      condition(:security_dashboard_enabled, scope: :subject) do
        @subject.feature_available?(:security_dashboard)
      end

      condition(:dependency_scanning_enabled, scope: :subject) do
        @subject.feature_available?(:dependency_scanning)
      end

      condition(:license_scanning_enabled, scope: :subject) do
        @subject.feature_available?(:license_scanning)
      end

      condition(:security_inventory_available, scope: :subject) do
        @subject.licensed_feature_available?(:security_inventory)
      end

      condition(:security_attributes_available, scope: :subject) do
        @subject.licensed_feature_available?(:security_attributes)
      end

      condition(:security_scan_profiles_available, scope: :subject) do
        @subject.licensed_feature_available?(:security_scan_profiles)
      end

      condition(:prevent_group_forking_available, scope: :subject) do
        @subject.feature_available?(:group_forking_protection)
      end

      condition(:needs_new_sso_session) do
        ::Gitlab::Auth::GroupSaml::SsoEnforcer.access_restricted?(user: @user, resource: @subject)
      end

      condition(:no_active_sso_session) do
        ::Gitlab::Auth::GroupSaml::SessionEnforcer.new(@user, @subject).access_restricted?
      end

      condition(:ip_enforcement_prevents_access, scope: :subject) do
        !::Gitlab::IpRestriction::Enforcer.new(subject).allows_current_ip?
      end

      condition(:cluster_deployments_available, scope: :subject) do
        @subject.feature_available?(:cluster_deployments)
      end

      condition(:global_saml_enabled, scope: :global) do
        ::Gitlab::Auth::Saml::Config.enabled?
      end

      condition(:global_saml_group_sync_enabled, scope: :global) do
        ::AuthHelper.saml_providers.any? do |provider|
          ::Gitlab::Auth::Saml::Config.new(provider).group_sync_enabled?
        end
      end

      condition(:group_saml_globally_enabled, scope: :global) do
        ::Gitlab::Auth::GroupSaml::Config.enabled?
      end

      condition(:group_saml_enabled, scope: :subject) do
        @subject.group_saml_enabled?
      end

      condition(:group_saml_available, scope: :subject) do
        !@subject.subgroup? && @subject.feature_available?(:group_saml)
      end

      condition(:saml_group_sync_available, scope: :subject) do
        @subject.saml_group_sync_available?
      end

      condition(:commit_committer_check_available, scope: :subject) do
        @subject.feature_available?(:commit_committer_check)
      end

      condition(:commit_committer_name_check_available, scope: :subject) do
        @subject.feature_available?(:commit_committer_name_check)
      end

      condition(:reject_unsigned_commits_available, scope: :subject) do
        @subject.feature_available?(:reject_unsigned_commits)
      end

      condition(:reject_non_dco_commits_available, scope: :subject) do
        @subject.feature_available?(:reject_non_dco_commits)
      end

      condition(:push_rules_available, scope: :subject) do
        @subject.feature_available?(:push_rules)
      end

      condition(:group_merge_request_approval_settings_enabled, scope: :subject) do
        @subject.feature_available?(:merge_request_approvers) && @subject.root?
      end

      condition(:read_only, scope: :subject) { @subject.read_only? }

      condition(:eligible_for_trial, scope: :subject) { @subject.eligible_for_trial? }

      condition(:compliance_framework_available, scope: :subject) do
        @subject.feature_available?(:custom_compliance_frameworks)
      end

      condition(:group_level_compliance_pipeline_available, scope: :subject) do
        @subject.feature_available?(:evaluate_group_level_compliance_pipeline)
      end

      condition(:security_orchestration_policies_enabled, scope: :subject) do
        ::Security::PolicyAvailability.any_available?(@subject)
      end

      condition(:group_level_compliance_dashboard_enabled, scope: :subject) do
        @subject.feature_available?(:group_level_compliance_dashboard)
      end

      condition(:group_level_compliance_adherence_report_enabled, scope: :subject) do
        @subject.feature_available?(:group_level_compliance_adherence_report)
      end

      condition(:group_level_compliance_violations_report_enabled, scope: :subject) do
        @subject.feature_available?(:group_level_compliance_violations_report)
      end

      condition(:trial_and_identity_verified) do
        if @subject.root_ancestor.trial_active?
          @user.identity_verified?
        else
          true
        end
      end

      condition(:user_banned_from_namespace) do
        next unless @user.is_a?(User)
        next if @user.can_admin_all_resources?

        # Loading the namespace_bans association is intentional because it is going to
        # be used in the banned_from_namespace? check below
        next if @user.namespace_bans.to_a.empty?

        root_namespace = @subject.root_ancestor
        next unless root_namespace.unique_project_download_limit_enabled?

        @user.banned_from_namespace?(root_namespace)
      end

      condition(:unique_project_download_limit_enabled) do
        @subject.unique_project_download_limit_enabled?
      end

      condition(:custom_roles_allowed) do
        @subject.custom_roles_enabled?
      end

      condition(:google_cloud_support_available, scope: :global) do
        ::Gitlab::Saas.feature_available?(:google_cloud_support)
      end

      condition(:allow_top_level_group_owners_to_create_service_accounts, scope: :global) do
        ::Gitlab::CurrentSettings.current_application_settings.allow_top_level_group_owners_to_create_service_accounts?
      end

      # score needs to be higher than reporter / developer / maintainer_access
      # so access_level condition is evaluated before any custom_role conditions
      MemberRole.all_customizable_group_permissions.each do |ability|
        desc "Custom role on group that enables #{ability.to_s.tr('_', ' ')}"
        condition(:"custom_role_enables_#{ability}", score: 65) do
          custom_role_ability(@user, @subject).allowed?(ability)
        end

        rule { cond(:"custom_role_enables_#{ability}") }.policy do
          enable(*::Authz::CustomAbility::Definition.new(ability).group_permissions)
        end
      end

      condition(:admin_custom_role_enables_read_admin_cicd, scope: :user) do
        ::Authz::CustomAbility.allowed?(@user, :read_admin_cicd)
      end

      condition(:admin_custom_role_enables_read_admin_groups, scope: :user) do
        ::Authz::CustomAbility.allowed?(@user, :read_admin_groups)
      end

      rule { admin_custom_role_enables_read_admin_groups }.policy do
        enable :read_group_metadata
      end

      rule { admin_custom_role_enables_read_admin_cicd }.policy do
        enable :read_group_metadata
      end

      condition(:generate_description_enabled) do
        ::Gitlab::Llm::FeatureAuthorizer.new(
          container: subject,
          feature_name: :generate_description,
          user: @user
        ).allowed?
      end

      condition(:summarize_notes_allowed) do
        next false unless @user

        ::Gitlab::Llm::FeatureAuthorizer.new(
          container: subject,
          feature_name: :summarize_comments,
          user: @user
        ).allowed?
      end

      rule { ~unique_project_download_limit_enabled }.prevent :ban_group_member

      condition(:security_policy_project_available) do
        @subject.security_orchestration_policy_configuration.present?
      end

      condition(:can_commit_to_security_policy_project) do
        security_orchestration_policy_configuration = @subject.security_orchestration_policy_configuration

        next unless security_orchestration_policy_configuration

        can?(:push_code, security_orchestration_policy_configuration.security_policy_management_project)
      end

      condition(:classic_chat_allowed_for_group, scope: :subject) do
        next true unless ::Gitlab::Saas.feature_available?(:duo_chat_on_saas)

        ::Gitlab::Llm::StageCheck.available?(@subject, :chat)
      end

      condition(:agentic_chat_allowed_for_group, scope: :subject) do
        ::Gitlab::Llm::StageCheck.available?(@subject, :agentic_chat)
      end

      condition(:ai_features_banned) do
        ::Gitlab::CurrentSettings.duo_never_on?
      end

      condition(:classic_chat_available_for_user) do
        next false unless @user

        @user.allowed_to_use?(:chat, unit_primitive_name: :duo_classic_chat, root_namespace: @subject.root_ancestor)
      end

      condition(:agentic_chat_available_for_user) do
        next false unless @user

        @user.allowed_to_use_for_resource?(:agentic_chat, unit_primitive_name: :duo_chat, resource: @subject)
      end

      condition(:duo_features_enabled, scope: :subject) { @subject.namespace_settings&.duo_features_enabled }

      condition(:duo_features_enabled_for_self_or_descendants, scope: :subject) do
        ::Ai::DuoWorkflow.duo_features_enabled_for_self_or_descendants?(@subject)
      end

      condition(:runner_performance_insights_available, scope: :subject) do
        @subject.licensed_feature_available?(:runner_performance_insights_for_namespace)
      end

      condition(:clickhouse_main_database_available, scope: :global) do
        ::Gitlab::ClickHouse.configured?
      end

      condition(:default_roles_assignees_allowed, scope: :subject) do
        @subject.root_ancestor.licensed_feature_available?(:default_roles_assignees)
      end

      condition(:resolve_vulnerability_allowed) do
        ::Gitlab::Llm::FeatureAuthorizer.new(
          container: subject,
          feature_name: :resolve_vulnerability,
          user: @user
        ).allowed?
      end

      condition(:ai_catalog_available_for_user) do
        # When anonymous user, delegates to the other setting controls.
        @user.nil? || @user.allowed_to_use_through_namespace?(:ai_catalog, @subject.root_ancestor)
      end

      condition(:ai_catalog_available) do
        @subject.duo_features_enabled && ::Gitlab::Llm::StageCheck.available?(@subject, :ai_catalog)
      end

      condition(:inherited_consumers_enabled, scope: :subject) do
        ::Feature.enabled?(:ai_catalog_group_inherited_consumers, @subject.root_ancestor)
      end

      condition(:provision_ai_catalog_allowed, scope: :subject) do
        @subject.duo_features_enabled || !@subject.namespace_settings&.duo_features_enabled_locked?(include_self: true)
      end

      rule { user_banned_from_namespace }.prevent_all

      rule { public_group | internal_access }.policy do
        enable :read_wiki
        enable :download_wiki_code
      end

      rule { ~group_analytics_dashboards_available | has_parent }.prevent :modify_value_stream_dashboard_settings

      rule { auditor }.policy do
        enable(*::Authz::Role.get(:auditor).direct_permissions(:group))
      end

      rule { ~group_ci_cd_analytics_releases_available }.policy do
        prevent :read_group_release_stats
      end

      rule { ~group_ci_cd_analytics_available }.policy do
        prevent :view_group_ci_cd_analytics
      end

      rule { can?(:read_cluster) & cluster_deployments_available }
        .enable :read_cluster_environments

      rule { has_access & contribution_analytics_available }.policy do
        enable :read_group_contribution_analytics
        enable :read_contribution_analytics
      end

      rule { has_access & group_activity_analytics_available }
        .enable :read_group_activity_analytics

      rule { ~dora4_analytics_available }.policy do
        prevent :read_dora4_analytics
      end

      condition(:ai_review_mr_enabled) do
        @subject.duo_features_enabled
      end

      condition(:user_allowed_to_use_ai_review_mr) do
        @user&.allowed_to_use?(
          :review_merge_request,
          licensed_feature: :review_merge_request,
          root_namespace: @subject.root_ancestor
        )
      end

      rule do
        ai_review_mr_enabled &
          user_allowed_to_use_ai_review_mr
      end.enable :access_ai_review_mr

      condition(:ai_analytics_available, scope: :subject) do
        @subject.feature_available?(:ai_analytics)
      end

      condition(:amazon_q_enabled) do
        ::Ai::AmazonQ.enabled?
      end

      rule { ~ai_analytics_available }.policy do
        prevent :read_pro_ai_analytics
        prevent :read_enterprise_ai_analytics
      end

      rule { ~group_repository_analytics_available }.policy do
        prevent :read_group_repository_analytics
      end

      rule { ~group_coverage_reports_available }.policy do
        prevent :read_group_coverage_reports
      end

      rule { ~group_analytics_dashboards_available }.policy do
        prevent :read_group_analytics_dashboards
      end

      rule { ~cycle_analytics_available }.policy do
        prevent :create_value_stream
        prevent :update_value_stream
        prevent :delete_value_stream
        prevent :read_cycle_analytics
        prevent :read_group_stage
        prevent :view_type_of_work_charts
      end

      rule { ~group_devops_adoption_enabled }.policy do
        prevent :manage_devops_adoption_namespaces
        prevent :view_group_devops_adoption
      end

      rule { ~admin & ~group_devops_adoption_available }.policy do
        prevent :manage_devops_adoption_namespaces
        prevent :view_group_devops_adoption
      end

      rule { has_parent | ~prevent_group_forking_available }.prevent :change_prevent_group_forking

      rule { can?(:read_group) & epics_available }.policy do
        enable :read_epic
        enable :read_epic_board
        enable :read_epic_board_list
      end

      rule { can?(:read_group) & iterations_available }.policy do
        enable :read_iteration
        enable :read_iteration_cadence
      end

      # Lets the support bot run iteration quick actions on service desk tickets in private groups
      rule { support_bot & iterations_available & has_project_with_service_desk_enabled }.policy do
        enable :read_iteration
        enable :read_iteration_cadence
      end

      rule { ~iterations_available }.policy do
        prevent :create_iteration
        prevent :admin_iteration
        prevent :create_iteration_cadence
        prevent :admin_iteration_cadence
        prevent :rollover_issues
      end

      rule { automation_bot }.enable :rollover_issues

      rule { ~epics_available }.policy do
        prevent :create_epic
        prevent :admin_epic
        prevent :bulk_admin_epic
        prevent :update_epic
        prevent :read_confidential_epic
        prevent :admin_epic_board
        prevent :admin_epic_board_list
        prevent :destroy_epic
      end

      rule { can?(:read_group) & custom_fields_available }.policy do
        enable :read_custom_field
      end

      rule { ~custom_fields_available }.prevent :admin_custom_field

      rule { ~can?(:read_cross_project) }.policy do
        prevent :read_group_contribution_analytics
        prevent :read_contribution_analytics
        prevent :read_epic
        prevent :read_confidential_epic
        prevent :create_epic
        prevent :admin_epic
        prevent :bulk_admin_epic
        prevent :update_epic
        prevent :destroy_epic
        prevent :admin_epic_board_list
      end

      rule { ~group_saml_globally_enabled | ~group_saml_available }.prevent :admin_group_saml

      rule { ~saml_group_sync_available & ~(global_saml_enabled & global_saml_group_sync_enabled) }.policy do
        prevent :admin_saml_group_links
      end

      rule { ~can_manage_ldap }.policy do
        prevent :create_ldap_group_link
        prevent :delete_ldap_group_link
        prevent :read_ldap_group_link
      end

      rule { ldap_synced }.policy do
        prevent :admin_group_member
        prevent :activate_group_member
        prevent :admin_member_access_request
        prevent :destroy_group_member
        prevent :invite_group_members
        prevent :read_member_access_request
      end

      rule { ~(ldap_synced & can_manage_ldap) }.prevent :override_group_member

      rule { memberships_locked_to_ldap & ~admin }.policy do
        prevent :admin_group_member
        prevent :destroy_project_bot_member
        prevent :activate_group_member
        prevent :admin_member_access_request
        prevent :invite_group_members
        prevent :read_member_access_request
        prevent :update_group_member
        prevent :override_group_member
      end

      rule { memberships_locked_to_saml & saml_group_sync_available & ~admin }.policy do
        prevent :admin_group_member
        prevent :destroy_project_bot_member
        prevent :activate_group_member
        prevent :admin_member_access_request
        prevent :invite_group_members
        prevent :read_member_access_request
      end

      rule { ~admin & ~allow_top_level_group_owners_to_create_service_accounts }.policy do
        prevent :create_service_account
        prevent :delete_service_account
        prevent :read_service_account
      end

      rule { ~admin & ~trial_and_identity_verified }.policy do
        prevent :admin_service_accounts
        prevent :admin_service_account_member
        prevent :create_service_account
        prevent :delete_service_account
      end

      rule { has_maintainer_projects }.policy do
        enable :read_ai_catalog_item_consumer
        enable :read_ai_catalog_flow
        enable :read_ai_foundational_flow
      end

      rule { ~security_orchestration_policies_enabled }.policy do
        prevent :create_security_policy
        prevent :modify_security_policy
        prevent :read_security_orchestration_policies
        prevent :update_security_orchestration_policy_project
      end

      rule { security_policy_project_available }.prevent :create_security_policy
      rule { ~can_commit_to_security_policy_project }.prevent :modify_security_policy
      rule { can_commit_to_security_policy_project }.enable :modify_security_policy

      rule { security_orchestration_policies_enabled & custom_role_enables_manage_security_policy_link }.policy do
        enable :read_security_orchestration_policies
        enable :read_security_orchestration_policy_project
        enable :update_security_orchestration_policy_project
      end

      condition(:policy_store_experiment_active, scope: :subject) do
        @subject.policy_store_experiment_active?
      end

      rule { ~policy_store_experiment_active }.policy do
        prevent :create_govern_policy
        prevent :read_govern_policy
        prevent :update_govern_policy
        prevent :delete_govern_policy
      end

      rule { ~dependency_scanning_enabled }.prevent :read_dependency, :read_advanced_dependency_management

      rule { ~license_scanning_enabled }.prevent :read_licenses

      rule { ~security_scan_profiles_available }.policy do
        prevent :read_security_scan_profiles
        prevent :apply_security_scan_profiles
        prevent :create_security_scan_profiles
        prevent :update_security_scan_profiles
        prevent :delete_security_scan_profiles
      end

      rule { ~security_inventory_available }.prevent :read_security_inventory

      rule { ~security_attributes_available }.policy do
        prevent :admin_security_attributes
        prevent :read_security_attribute
      end

      rule { ~security_dashboard_enabled }.policy do
        prevent :access_security_and_compliance
        prevent :admin_vulnerability
        prevent :confirm_vulnerability
        prevent :dismiss_vulnerability
        prevent :resolve_vulnerability
        prevent :revert_vulnerability
        prevent :update_vulnerability_severity
        prevent :create_vulnerability_export
        prevent :read_group_security_dashboard
        prevent :read_security_configuration
        prevent :read_security_resource
        prevent :read_vulnerability
        prevent :read_vulnerability_statistics
      end

      rule { ~resource_access_token_feature_available }.policy do
        prevent :read_resource_access_tokens
        prevent :destroy_resource_access_tokens
      end

      rule { ~resource_access_token_creation_allowed }.policy do
        prevent :create_resource_access_tokens
        prevent :manage_resource_access_tokens
      end

      rule { ~default_roles_assignees_allowed & ~custom_roles_allowed }.prevent :view_member_roles

      rule { ~custom_roles_allowed }.policy do
        prevent :admin_member_role
        prevent :read_member_role
      end

      rule { ~is_gitlab_com }.prevent :admin_member_role

      rule { ~compliance_framework_available }.policy do
        prevent :admin_compliance_framework
        prevent :read_compliance_framework
      end

      rule { ~group_level_compliance_pipeline_available }.policy do
        prevent :read_compliance_pipeline_configuration
        prevent :update_compliance_pipeline_configuration
      end

      rule { ~group_level_compliance_dashboard_enabled }.policy do
        prevent :read_compliance_dashboard
        prevent :read_agent_artifacts
      end

      rule { ~group_level_compliance_adherence_report_enabled }.policy do
        prevent :read_compliance_adherence_report
      end

      rule { ~group_level_compliance_violations_report_enabled }.policy do
        prevent :read_compliance_violations_report
        prevent :update_compliance_violations_report
      end

      condition(:any_projects_except_soft_deleted) do
        @subject.all_projects.non_archived.not_aimed_for_deletion.exists?
      end

      rule { can?(:_delete_subgroup) & has_parent }.policy do
        enable :remove_group
      end

      rule { can?(:_archive_subgroup) & has_parent }.policy do
        enable :archive_group
      end

      rule { ~admin & owner_cannot_destroy_project & any_projects_except_soft_deleted }.policy do
        prevent :remove_group
      end

      rule { can?(:manage_deploy_tokens) | can?(:manage_merge_request_settings) }.policy do
        enable :view_edit_page
      end

      rule { can?(:read_security_resource) & resolve_vulnerability_allowed }.policy do
        enable :resolve_vulnerability_with_ai
      end

      rule { ~group_credentials_inventory_available | has_parent }.policy do
        prevent :read_group_credentials_inventory
        prevent :revoke_personal_access_token
      end

      rule { ~group_merge_request_approval_settings_enabled }.policy do
        prevent :read_merge_request_approval_setting
        prevent :update_merge_request_approval_setting
        prevent :update_approval_rule
      end

      rule { locked_approval_rules & ~admin }.policy do
        prevent :create_approval_rule
        prevent :update_approval_rule
        prevent :delete_approval_rule
      end

      rule { needs_new_sso_session }.policy do
        prevent :read_group
      end

      rule { ip_enforcement_prevents_access & ~can?(:_bypass_ip_enforcement) }.policy do
        prevent_all do
          except :_bypass_ip_enforcement
        end
      end

      rule { ~group_saml_enabled }.policy do
        prevent :read_group_saml_identity
        prevent :read_group_scim_identity
      end

      rule { ~(admin | allow_to_manage_default_branch_protection) }.policy do
        prevent :update_default_branch_protection
      end

      desc "Group has wiki disabled"
      condition(:wiki_disabled, score: 32) do
        !@subject.licensed_feature_available?(:group_wikis) || !@subject.feature_available?(:wiki, @user)
      end

      desc "Group has saved replies support"
      condition(:supports_saved_replies) do
        @subject.supports_saved_replies?
      end

      rule { wiki_disabled }.policy do
        prevent :read_wiki
        prevent :create_wiki
        prevent :update_wiki
        prevent :admin_wiki
        prevent :destroy_wiki
        prevent :download_wiki_code
      end

      rule { ~push_rules_available }.policy do
        prevent :change_push_rules
      end

      rule { ~commit_committer_check_available }.policy do
        prevent :change_commit_committer_check
      end

      rule { ~commit_committer_name_check_available }.policy do
        prevent :change_commit_committer_name_check
      end

      rule { ~reject_unsigned_commits_available }.policy do
        prevent :change_reject_unsigned_commits
      end

      rule { ~reject_non_dco_commits_available }.policy do
        prevent :change_reject_non_dco_commits
      end

      rule { admin & is_gitlab_com }.enable :update_subscription_limit

      rule { ~eligible_for_trial }.prevent :start_trial

      rule { read_only }.policy do
        prevent :create_epic
        prevent :update_epic
        prevent :admin_pipeline
        prevent :register_group_runners
        prevent :create_runners
        prevent :add_cluster
        prevent :create_cluster
        prevent :update_cluster
        prevent :admin_cluster
        prevent :create_deploy_token
        prevent :create_subgroup
        prevent :create_package
      end

      rule { ~group_membership_export_available }.prevent :export_group_memberships

      rule { ~external_audit_events_available }.prevent :admin_external_audit_events

      # Special case to allow support bot assigning service desk
      # issues to epics in private groups using quick actions
      rule { support_bot & epics_available & has_project_with_service_desk_enabled }.policy do
        enable :read_epic
        enable :read_issue
        enable :read_epic_iid
      end

      rule { can?(:read_group) & classic_chat_allowed_for_group & classic_chat_available_for_user & duo_features_enabled }.enable :access_duo_classic_chat

      rule do
        can?(:read_group) &
          agentic_chat_allowed_for_group &
          agentic_chat_available_for_user &
          duo_features_enabled &
          duo_agent_platform_enabled &
          ~amazon_q_enabled
      end.enable :access_duo_agentic_chat

      rule do
        check_customizable_ai_settings &
          below_minimum_access_level_execute
      end.prevent :access_duo_agentic_chat

      condition(:check_customizable_ai_settings) do
        customizable_permissions_enabled? &&
          !can?(:update_organization, @subject.organization)
      end

      condition(:below_minimum_access_level_execute) do
        minimum_access_level_execute = @subject.root_ancestor.ai_minimum_access_level_execute_with_fallback
        next false if minimum_access_level_execute.nil?

        access_level < minimum_access_level_execute
      end

      rule { ai_features_banned }.policy do
        prevent :access_duo_classic_chat
        prevent :access_duo_agentic_chat
        prevent :access_code_suggestions
      end

      rule { can?(:read_group) & code_suggestions_enabled_for_user }.enable :access_code_suggestions

      rule { ~code_suggestions_licensed }.prevent :access_code_suggestions
      rule { ~duo_features_enabled }.prevent :access_code_suggestions

      rule { can?(:read_group) & duo_features_enabled }.enable :access_duo_features

      # Grants live in the role YAMLs (config/authz/roles/), not here; this block only withholds.
      rule { ~duo_features_enabled }.policy do
        prevent :read_ai_tool_rule
        prevent :update_ai_tool_rule
        prevent :block_ai_catalog_mcp_server
      end

      rule { ~supports_saved_replies }.policy do
        prevent :read_saved_reply
        prevent :create_saved_reply
        prevent :delete_saved_reply
        prevent :update_saved_reply
      end

      rule { ~google_cloud_support_available }.policy do
        prevent :read_runner_cloud_provisioning_info
        prevent :read_runner_gke_provisioning_info
        prevent :provision_cloud_runner
        prevent :provision_gke_runner
      end

      rule { ~runner_performance_insights_available }.policy do
        prevent :read_runner_usage
        prevent :read_jobs_statistics
      end

      rule { ~clickhouse_main_database_available }.prevent :read_runner_usage

      condition(:secret_push_protection_available) do
        @subject.licensed_feature_available?(:secret_push_protection)
      end

      rule { ~secret_push_protection_available }.prevent :enable_secret_push_protection

      condition(:validity_checks_available, scope: :subject) do
        @subject.licensed_feature_available?(:secret_detection_validity_checks)
      end

      rule { ~validity_checks_available }.prevent :update_secret_detection_validity_check

      condition(:disable_invite_group_members, scope: :subject) do
        if ::Gitlab::Saas.feature_available?(:group_disable_invite_members)
          @subject.licensed_feature_available?(:disable_invite_members) &&
            @subject.root_ancestor.disable_invite_members?
        else
          ::License.feature_available?(:disable_invite_members) &&
            ::Gitlab::CurrentSettings.current_application_settings.disable_invite_members?
        end
      end

      rule { ~admin & disable_invite_group_members }.policy do
        prevent :invite_group_members
        prevent :create_group_link
      end

      rule { ~duo_workflow_available }.policy do
        prevent :admin_duo_workflow
        prevent :create_duo_workflow_for_ci
        prevent :duo_workflow
        prevent :manage_ai_flow_triggers
        prevent :read_ai_flow_triggers
      end

      rule { ~duo_agent_platform_enabled }.policy do
        prevent :create_duo_workflow_for_ci
        prevent :duo_workflow
      end

      rule { duo_workflow_token & ~duo_features_enabled_for_self_or_descendants }.prevent_all

      rule do
        summarize_notes_allowed & can?(:read_work_item)
      end.enable :summarize_comments

      rule do
        generate_description_enabled & can?(:create_work_item)
      end.enable :generate_description

      condition(:orbit_setting_changeable, scope: :subject) do
        @subject.root? && ::Analytics::Orbit::Billing.account_for(@subject).setting_changeable?(@subject)
      end

      condition(:orbit_trial_offered, scope: :subject) do
        @subject.root? && ::Analytics::Orbit::Billing.account_for(@subject).trial_offered_to?(@subject)
      end

      condition(:orbit_trial_startable, scope: :subject) do
        @subject.root? && ::Analytics::Orbit::Billing.account_for(@subject).trial_startable_by?(@subject)
      end

      condition(:claude_code_compliance_api_ingestion_enabled, scope: :subject) do
        ::Feature.enabled?(:claude_code_compliance_api_ingestion, @subject)
      end

      with_scope :subject
      condition(:group_model_selection_enabled) do
        next false unless subject.root?
        next false if ::Ai::Setting.self_hosted?
        next false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        next false if ::Ai::AmazonQ.connected?
        next false if subject.has_free_or_no_subscription?

        subject.namespace_settings&.duo_features_enabled?
      end

      condition(:ai_catalog_skills_enabled, scope: :subject) do
        ::Feature.enabled?(:ai_catalog_skills, @subject)
      end

      condition(:third_party_flows_enabled, scope: :user) do
        ::Feature.enabled?(:ai_catalog_third_party_flows, @user)
      end

      condition(:foundational_flows_available, scope: :subject) do
        @subject.foundational_flows_available?
      end

      condition(:flows_available, scope: :subject) do
        ::Gitlab::Llm::StageCheck.available?(@subject, :ai_catalog_flows)
      end

      condition(:third_party_flows_available, scope: :subject) do
        ::Gitlab::Llm::StageCheck.available?(@subject, :ai_catalog_third_party_flows)
      end

      condition(:duo_custom_flows_enabled, scope: :subject) do
        @subject.root_ancestor.duo_custom_flows_enabled
      end

      condition(:duo_custom_agents_enabled, scope: :subject) do
        @subject.root_ancestor.duo_custom_agents_enabled
      end

      rule { ~inherited_consumers_enabled }.policy do
        prevent :read_ai_flow_triggers
        prevent :manage_ai_flow_triggers
      end

      rule { ~ai_catalog_available_for_user | ~ai_catalog_available }.policy do
        prevent :create_ai_catalog_flow_item_consumer
        prevent :create_ai_catalog_third_party_flow_item_consumer
        prevent :admin_ai_catalog_item_consumer
        prevent :read_ai_catalog_item_consumer
        prevent :read_ai_flow_triggers
        prevent :manage_ai_flow_triggers
        prevent :read_ai_catalog_item
        prevent :execute_ai_catalog_item
        prevent :read_ai_catalog_flow
        prevent :read_ai_catalog_third_party_flow
        prevent :create_ai_catalog_agent_item_consumer
        prevent :create_ai_catalog_skill_item_consumer
      end

      rule { ~provision_ai_catalog_allowed }.policy do
        prevent :provision_ai_catalog
        prevent :create_ai_catalog_item_consumer
      end

      rule { ~foundational_flows_available | ~ai_catalog_available_for_user }.policy do
        prevent :read_ai_foundational_flow
        prevent :create_ai_foundational_flow_item_consumer
      end

      rule { ~flows_available }.policy do
        prevent :read_ai_catalog_flow
        prevent :create_ai_catalog_flow_item_consumer
      end

      rule { ~duo_custom_flows_enabled }.policy do
        prevent :create_ai_catalog_flow_item_consumer
      end

      rule { ~duo_custom_agents_enabled }.policy do
        prevent :create_ai_catalog_agent_item_consumer
      end

      rule { ~ai_catalog_skills_enabled }.prevent :create_ai_catalog_skill_item_consumer

      rule { ~third_party_flows_enabled | ~third_party_flows_available }.policy do
        prevent :read_ai_catalog_third_party_flow
        prevent :create_ai_catalog_third_party_flow_item_consumer
      end

      condition(:duo_external_agents_enabled, scope: :subject) do
        @subject.root_ancestor.duo_external_agents_enabled
      end

      rule { ~duo_external_agents_enabled }.policy do
        prevent :create_ai_catalog_third_party_flow_item_consumer
      end

      rule { ~group_model_selection_enabled }.policy do
        prevent :admin_group_model_selection
        prevent :read_model_selection_allowlist
        prevent :update_model_selection_allowlist
      end

      rule { ~orbit_setting_changeable }.prevent :update_knowledge_graph_setting

      rule { ~is_root_namespace }.policy do
        prevent :read_orbit_setting
        prevent :update_duo_in_slack
      end

      rule { ~orbit_trial_offered }.policy do
        prevent :read_orbit_trial
        prevent :start_orbit_trial
      end

      rule { ~orbit_trial_startable }.prevent :start_orbit_trial

      rule { has_parent }.prevent :update_ai_domain_settings

      rule { has_parent | ~claude_code_compliance_api_ingestion_enabled }.policy do
        prevent :read_anthropic_compliance_integration
        prevent :create_anthropic_compliance_integration
        prevent :update_anthropic_compliance_integration
        prevent :delete_anthropic_compliance_integration
      end

      condition(:group_secrets_manager_enabled) do
        ::SecretsManagement::Availability.for_group?(@subject)
      end

      rule { ~group_secrets_manager_enabled }.policy do
        prevent :create_secret
        prevent :create_secrets_manager_api_jwt
        prevent :delete_secret
        prevent :delete_secrets_permission
        prevent :deprovision_secrets_manager
        prevent :provision_secrets_manager
        prevent :read_group_secrets_manager_status
        prevent :read_secret
        prevent :read_secrets_manager
        prevent :read_secrets_permission
        prevent :update_secret
        prevent :update_secrets_permission
      end

      condition(:secrets_manager_entitlement_denies_access, score: SECRETS_MANAGER_ENTITLEMENT_SCORE) do
        group_secrets_manager_enabled? &&
          !secrets_manager_entitlement.permits_read?
      end

      # Narrower than `secrets_manager_entitlement_denies_access`: gates the
      # non-CI/CD REST access-token endpoint, which hands the client a JWT to
      # read straight from OpenBao (the same direct-access pattern CI uses).
      condition(:secrets_manager_entitlement_denies_direct_read, score: SECRETS_MANAGER_ENTITLEMENT_SCORE) do
        group_secrets_manager_enabled? &&
          !secrets_manager_entitlement.permits_direct_read?
      end

      condition(:secrets_manager_entitlement_denies_writes, score: SECRETS_MANAGER_ENTITLEMENT_SCORE) do
        group_secrets_manager_enabled? &&
          !secrets_manager_entitlement.permits_writes?
      end

      # Subgroups stay hidden until the top-level group's entitlement
      # transitions past `trial_eligible`, except for the free-beta cohort,
      # which keeps visibility of the secrets it created during the beta.
      # `beta_window_eligible` is the resolver's realm-aware beta signal
      # (namespace enrollment on SaaS, instance enrollment on self-managed).
      condition(:secrets_manager_entitlement_trial_eligible_on_non_root_group,
        score: SECRETS_MANAGER_ENTITLEMENT_SCORE) do
        group_secrets_manager_enabled? &&
          !@subject.root? && secrets_manager_entitlement.state == :trial_eligible &&
          !secrets_manager_entitlement.beta_window_eligible
      end

      rule { secrets_manager_entitlement_denies_access }.policy do
        prevent :read_secret
        prevent :read_secrets_permission
        prevent :create_secret
        prevent :update_secret
        prevent :delete_secret
        prevent :provision_secrets_manager
        prevent :deprovision_secrets_manager
        prevent :update_secrets_permission
        prevent :delete_secrets_permission
      end

      rule { secrets_manager_entitlement_denies_direct_read }.prevent :create_secrets_manager_api_jwt

      # Delete is not here on purpose: the billing entitlement only blocks deletes
      # when it blocks reads (`secrets_manager_entitlement_denies_access`). Role
      # and OpenBao ACL checks for delete are unaffected.
      rule { secrets_manager_entitlement_denies_writes }.policy do
        prevent :create_secret
        prevent :update_secret
        prevent :provision_secrets_manager
        prevent :deprovision_secrets_manager
        prevent :update_secrets_permission
        prevent :delete_secrets_permission
      end

      rule { secrets_manager_entitlement_trial_eligible_on_non_root_group }.policy do
        prevent :read_secret
        prevent :delete_secret
        prevent :read_secrets_manager
        prevent :read_secrets_permission
        prevent :read_group_secrets_manager_status
        prevent :create_secrets_manager_api_jwt
      end

      condition(:namespace_enrollment_allowed) do
        ::SecretsManagement::NamespaceEnrollment.enrollment_allowed?(@subject)
      end

      rule { ~namespace_enrollment_allowed }.policy do
        prevent :create_secrets_manager_enrollment
        prevent :delete_secrets_manager_enrollment
        prevent :enable_secrets_manager_add_on
        prevent :read_secrets_manager_enrollment
        # The trial flow enrolls the namespace first, so it shares the enrollment gate.
        prevent :start_secrets_manager_trial
      end

      # Below Maintainer, the entitlement is readable only in the states where its secrets are.
      rule do
        can?(:_read_secrets_manager_entitlement) &
          ~secrets_manager_entitlement_denies_access &
          ~secrets_manager_entitlement_trial_eligible_on_non_root_group
      end.enable :read_secrets_manager_entitlement

      # After an opt-out, only users who can re-enroll keep it, so group settings can offer re-enrollment.
      rule { ~group_secrets_manager_enabled & ~can?(:read_secrets_manager_enrollment) }.policy do
        prevent :read_secrets_manager_entitlement
      end

      # Same check as OrganizationPolicy, so caps are never locked for both group and Organization owners.
      condition(:billed_through_organization, scope: :subject) do
        ::GitlabSubscriptions::OrganizationBilling.active?(@subject.organization)
      end

      rule { billed_through_organization & ~admin }.prevent :update_subscription_usage_cap
    end

    override :lookup_access_level!
    def lookup_access_level!(for_any_session: false)
      if for_any_session
        return ::GroupMember::NO_ACCESS if no_active_sso_session?
      elsif needs_new_sso_session?
        return ::GroupMember::NO_ACCESS
      end

      super
    end

    override :can_read_group_member?
    def can_read_group_member?
      return true if user&.can_read_all_resources?

      super
    end

    # Available in Core for self-managed but only paid, non-trial for .com to prevent abuse
    override :resource_access_token_create_feature_available?
    def resource_access_token_create_feature_available?
      return false unless resource_access_token_feature_available?
      return super unless ::Gitlab.com?

      group.feature_available_non_trial?(:resource_access_token)
    end

    override :resource_access_token_feature_available?
    def resource_access_token_feature_available?
      return false if ::Gitlab::CurrentSettings.personal_access_tokens_disabled?

      super
    end

    def custom_role_ability(user, subject)
      strong_memoize_with(:custom_role_ability, user, subject) do
        ::Authz::CustomAbility.new(user, subject)
      end
    end

    def secrets_manager_entitlement
      strong_memoize_with(:secrets_manager_entitlement, subject, user) do
        root = subject.root_ancestor
        ::SecretsManagement::Entitlement.for(root.is_a?(::Group) ? root : nil, user: user)
      end
    end

    def customizable_permissions_enabled?
      if is_gitlab_com?
        ::Feature.enabled?(:dap_group_customizable_permissions, group.root_ancestor)
      else
        ::Feature.enabled?(:dap_instance_customizable_permissions, :instance)
      end
    end
  end
end
