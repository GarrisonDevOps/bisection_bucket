# frozen_string_literal: true

module EE
  module ProjectPolicy
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    # Run after the role checks: these conditions call CustomersDot, and with a
    # lower score DeclarativePolicy evaluates them even for non-members.
    SECRETS_MANAGER_ENTITLEMENT_SCORE = 64

    prepended do
      include ReadonlyAbilities
      include ::Gitlab::Utils::StrongMemoize
      include Vulnerabilities::AdvancedVulnerabilityManagementPolicy
      include ::Sbom::AdvancedDependencyManagementPolicy
      include ::WorkItems::SharedPolicy
      include ::Ci::JobAbilities
      include ::Ai::Catalog::McpServers::NamespacePolicy
      include ::Ai::DuoAgentPlatform::AccessPolicy

      desc "User is a security policy bot on the project"
      condition(:security_policy_bot) { user&.security_policy_bot? && team_member? }

      desc "User is a security policy bot accessing via job token (cross-project)"
      condition(:security_policy_bot_via_job_token) do
        user&.security_policy_bot? &&
          user.from_ci_job_token? &&
          project.ci_inbound_job_token_scope_enabled? &&
          project_allowed_for_job_token_by_scope?
      end

      desc "User is the dependency management service account on the project"
      condition(:dependency_management_service_account) do
        user.is_a?(User) &&
          user.service_account? &&
          team_member? &&
          @subject.dependency_management_service_account&.id == user.id
      end

      with_scope :subject
      condition(:repository_mirrors_enabled) { @subject.feature_available?(:repository_mirrors) }

      condition(:pull_mirror_available, scope: :subject) { @subject.pull_mirror_available? }

      with_scope :subject
      condition(:iterations_available) { @subject.group&.licensed_feature_available?(:iterations) }

      condition(:requirements_available) { @subject.feature_available?(:requirements) & access_allowed_to?(:requirements) }

      with_scope :subject
      condition(:quality_management_available) { @subject.feature_available?(:quality_management) }

      condition(:compliance_framework_available) { @subject.feature_available?(:compliance_framework, @user) }

      with_scope :subject
      condition(:project_level_compliance_dashboard_enabled) do
        in_group? && @subject.feature_available?(:project_level_compliance_dashboard)
      end

      with_scope :subject
      condition(:project_level_compliance_adherence_report_enabled) do
        in_group? && @subject.feature_available?(:project_level_compliance_adherence_report)
      end

      with_scope :subject
      condition(:project_level_compliance_violations_report_enabled) do
        in_group? && @subject.feature_available?(:project_level_compliance_violations_report)
      end

      with_scope :subject
      condition(:project_epics_available) do
        @subject.project_epics_enabled? && @subject.licensed_feature_available?(:epics)
      end

      with_scope :subject
      condition(:disable_invite_members_for_group) do
        ::Gitlab::Saas.feature_available?(:group_disable_invite_members) &&
          @subject.group &&
          @subject.group.root_ancestor.licensed_feature_available?(:disable_invite_members) &&
          @subject.group.root_ancestor.disable_invite_members?
      end

      with_scope :global
      condition(:disable_invite_members) do
        License.feature_available?(:disable_invite_members) &&
          ::Gitlab::CurrentSettings.current_application_settings.disable_invite_members?
      end

      condition(:group_merge_request_approval_settings_enabled, scope: :subject) do
        @subject.feature_available?(:merge_request_approvers)
      end

      with_scope :global
      condition(:locked_merge_request_author_setting) do
        License.feature_available?(:admin_merge_request_approvers_rules) &&
          ::Gitlab::CurrentSettings.prevent_merge_requests_author_approval
      end

      with_scope :global
      condition(:locked_merge_request_committer_setting) do
        License.feature_available?(:admin_merge_request_approvers_rules) &&
          ::Gitlab::CurrentSettings.prevent_merge_requests_committers_approval
      end

      with_scope :subject
      condition(:dora4_analytics_available) do
        @subject.feature_available?(:dora4_analytics)
      end

      condition(:project_merge_request_analytics_available, scope: :subject) do
        @subject.feature_available?(:project_merge_request_analytics)
      end

      condition(:push_rules_available, scope: :subject) do
        @subject.feature_available?(:push_rules)
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

      condition(:security_orchestration_policies_enabled, scope: :subject) do
        ::Security::PolicyAvailability.any_available?(@subject)
      end

      condition(:policy_store_experiment_active, scope: :subject) do
        @subject.policy_store_experiment_active?
      end

      rule { ~policy_store_experiment_active }.prevent :read_govern_policy

      condition(:security_dashboard_enabled, scope: :subject) do
        @subject.feature_available?(:security_dashboard)
      end

      condition(:security_scans_api_enabled, scope: :subject) do
        ::Gitlab::Saas.feature_available?(:security_scans_api) &&
          @subject.licensed_feature_available?(:security_scans_api)
      end

      condition(:security_scan_profiles_available, scope: :subject) do
        @subject.licensed_feature_available?(:security_scan_profiles)
      end

      condition(:sec_ai_workflow_settings_permission_available, scope: :subject) do
        ::Feature.enabled?(:update_sast_vr_setting_permission, @subject) ||
          ::Feature.enabled?(:update_false_positive_detection_setting_permission, @subject)
      end

      rule { ~sec_ai_workflow_settings_permission_available }.prevent :update_sec_ai_workflow_settings

      condition(:security_attributes_available, scope: :subject) do
        @subject.licensed_feature_available?(:security_attributes)
      end

      condition(:security_inventory_available, scope: :subject) do
        @subject.licensed_feature_available?(:security_inventory)
      end

      condition(:coverage_fuzzing_enabled, scope: :subject) do
        @subject.feature_available?(:coverage_fuzzing)
      end

      condition(:on_demand_scans_enabled, scope: :subject) do
        @subject.on_demand_dast_available?
      end

      condition(:license_scanning_enabled, scope: :subject) do
        @subject.feature_available?(:license_scanning)
      end

      condition(:dependency_scanning_enabled, scope: :subject) do
        @subject.feature_available?(:dependency_scanning)
      end

      condition(:code_review_analytics_enabled) do
        @subject.feature_available?(:code_review_analytics, @user)
      end

      condition(:issue_analytics_enabled) do
        @subject.feature_available?(:issues_analytics, @user)
      end

      condition(:project_level_analytics_dashboard_enabled) do
        @subject.feature_available?(:project_level_analytics_dashboard, @user)
      end

      condition(:google_cloud_support_available, scope: :global) do
        ::Gitlab::Saas.feature_available?(:google_cloud_support)
      end

      condition(:status_page_available) do
        @subject.feature_available?(:status_page, @user)
      end

      condition(:read_only, scope: :subject) do
        @subject.root_namespace.read_only?
      end

      condition(:feature_flags_related_issues_disabled, scope: :subject) do
        !@subject.feature_available?(:feature_flags_related_issues)
      end

      condition(:oncall_schedules_available, scope: :subject) do
        ::Gitlab::IncidentManagement.oncall_schedules_available?(@subject)
      end

      condition(:escalation_policies_available, scope: :subject) do
        ::Gitlab::IncidentManagement.escalation_policies_available?(@subject)
      end

      condition(:hidden, scope: :subject) do
        @subject.hidden?
      end

      condition(:membership_locked_via_parent_group, scope: :subject) do
        @subject.group && (
          @subject.group.membership_lock? ||
          ::Gitlab::CurrentSettings.lock_memberships_to_ldap? ||
          ::Gitlab::CurrentSettings.lock_memberships_to_saml)
      end

      condition(:any_security_policy_project_available, scope: :subject) do
        all_security_policy_configurations.present?
      end

      condition(:direct_security_policy_project_available, scope: :subject) do
        @subject.security_orchestration_policy_configuration.present?
      end

      condition(:can_commit_to_security_policy_project) do
        security_orchestration_policy_configuration = @subject.security_orchestration_policy_configuration

        next unless security_orchestration_policy_configuration

        can?(:push_code, security_orchestration_policy_configuration.security_policy_management_project)
      end

      condition(:can_commit_to_any_security_policy_project) do
        all_security_policy_configurations.any? do |configuration|
          Ability.allowed?(@user, :push_code, configuration.security_policy_management_project)
        end
      end

      condition(:okrs_enabled, scope: :subject) do
        @subject.okrs_mvc_feature_flag_enabled? && @subject.feature_available?(:okrs)
      end

      condition(:licensed_cycle_analytics_available, scope: :subject) do
        @subject.feature_available?(:cycle_analytics_for_projects)
      end

      condition(:user_banned_from_namespace) do
        next unless @user.is_a?(User)
        next if @user.can_admin_all_resources?
        # Loading the namespace_bans association is intentional because it is going to
        # be used in the banned_from_namespace? check below
        next if @user.namespace_bans.to_a.empty?

        groups = @subject.invited_groups + [@subject.group]
        groups.compact!
        next if groups.empty?

        groups.any? do |group|
          next unless group.root_ancestor.unique_project_download_limit_enabled?

          @user.banned_from_namespace?(group.root_ancestor)
        end
      end

      rule { membership_locked_via_parent_group }.policy do
        prevent :import_project_members_from_another_project
        prevent :invite_member
      end

      condition(:memberships_locked_to_saml, scope: :global) do
        ::Gitlab::CurrentSettings.lock_memberships_to_saml?
      end

      condition(:saml_group_sync_available, scope: :subject) do
        @subject.group&.saml_group_sync_available?
      end

      rule { memberships_locked_to_saml & saml_group_sync_available & ~admin }.policy do
        prevent :admin_project_member
        prevent :destroy_project_member
      end

      condition(:custom_roles_allowed, scope: :subject) do
        @subject.custom_roles_enabled?
      end

      # score needs to be higher than reporter / developer / maintainer_access
      # so access_level condition is evaluated before any custom_role conditions
      MemberRole.all_customizable_project_permissions.each do |ability|
        desc "Custom role on project that enables #{ability.to_s.tr('_', ' ')}"
        condition(:"custom_role_enables_#{ability}", score: 210) do
          custom_role_ability(@user, @subject).allowed?(ability)
        end

        rule { cond(:"custom_role_enables_#{ability}") }.policy do
          enable(*::Authz::CustomAbility::Definition.new(ability).project_permissions)
        end
      end

      ::Gitlab::CustomRoles::Definition.admin.each_key do |ability|
        desc "Admin custom role that enables #{ability.to_s.tr('_', ' ')}"
        condition(:"admin_custom_role_enables_#{ability}", scope: :user) do
          ::Authz::CustomAbility.new(@user).allowed?(ability)
        end
      end

      condition(:summarize_new_merge_request_enabled) do
        ::Feature.enabled?(:add_ai_summary_for_new_mr, subject) &&
          ::Gitlab::Llm::FeatureAuthorizer.new(
            container: subject,
            feature_name: :summarize_new_merge_request,
            user: @user,
            licensed_feature: :summarize_new_merge_request
          ).allowed?
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

      with_scope :subject
      condition(:target_branch_rules_available) { subject.licensed_feature_available?(:target_branch_rules) }

      condition(:pages_multiple_versions_available, scope: :subject) do
        @subject.licensed_feature_available?(:pages_multiple_versions)
      end

      condition(:merge_requests_is_a_private_feature, scope: :subject) do
        project.project_feature&.private?(:merge_requests)
      end

      condition(:observability_enabled, scope: :subject) do
        ::Feature.enabled?(:observability_features, @subject.root_namespace) &&
          @subject.licensed_feature_available?(:observability)
      end

      # We are overriding the already defined condition in CE version
      # to allow Guest users with member roles to access the merge requests.
      condition(:merge_requests_disabled) do
        !(access_allowed_to?(:merge_requests) ||
          (merge_requests_is_a_private_feature? && custom_role_enables_admin_merge_request?))
      end

      condition(:trial_and_identity_verified) do
        if @subject.group&.root_ancestor&.trial_active?
          @user.identity_verified?
        else
          true
        end
      end

      # Prevent in case parent group belongs to trial subscription
      rule { ~admin & ~trial_and_identity_verified }.policy do
        prevent :admin_service_accounts
        prevent :admin_service_account_member
        prevent :create_service_account
        prevent :delete_service_account
      end

      rule { admin_custom_role_enables_read_admin_projects }.policy do
        enable :read_project_metadata
      end

      rule { admin_custom_role_enables_read_admin_cicd }.policy do
        enable :read_project_metadata
      end

      condition(:ci_cancellation_maintainers_only, scope: :subject) do
        project.ci_cancellation_restriction.maintainers_only_allowed?
      end

      condition(:ci_cancellation_no_one, scope: :subject) do
        project.ci_cancellation_restriction.no_one_allowed?
      end

      condition(:classic_chat_allowed_for_parent_group, scope: :subject) do
        next true unless ::Gitlab::Saas.feature_available?(:duo_chat_on_saas)

        ::Gitlab::Llm::StageCheck.available?(@subject, :chat)
      end

      condition(:agentic_chat_allowed_for_parent_group, scope: :subject) do
        ::Gitlab::Llm::StageCheck.available?(@subject, :agentic_chat)
      end

      condition(:ai_features_banned, scope: :global) do
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

      condition(:duo_features_enabled, scope: :subject) { @subject.duo_features_enabled }

      # Grants live in the role YAMLs (config/authz/roles/), not here; this block only withholds.
      # The MCP block is scoped tighter than the tool rules on purpose: a group block cascades and
      # cannot be undone at project level, while a tool rule stays correctable by the group Owner.
      rule { ~duo_features_enabled }.policy do
        prevent :read_ai_tool_rule
        prevent :update_ai_tool_rule
        prevent :block_ai_catalog_mcp_server
      end

      condition(:security_policy_project, scope: :subject) do
        Security::OrchestrationPolicyConfiguration.policy_management_project?(@subject.id)
      end

      rule { auditor }.policy do
        enable(*::Authz::Role.get(:auditor).permissions(:project))
      end

      # A group owner can delete the personal projects of their enterprise users
      # when destroying the enterprise user account. Delegates to :destroy_user so
      # all enterprise checks (including managed_by_group?) stay in EE::UserPolicy
      # and cannot drift.
      desc "User can destroy the owner of this personal project"
      condition(:can_destroy_personal_project_owner) do
        next false unless user
        next false unless @subject.personal?

        project_owner = @subject.owner
        next false unless project_owner

        can?(:destroy_user, project_owner)
      end

      rule { can_destroy_personal_project_owner }.enable :remove_project

      rule { visual_review_bot }.policy do
        prevent_all
      end

      rule { license_block }.policy do
        prevent :create_issue
        prevent :create_merge_request_from
        prevent :create_merge_request_in
        prevent :create_repository_tag
        prevent :delete_repository_tag
        prevent :push_code
        prevent :update_repository_tag
      end

      rule { analytics_disabled }.policy do
        prevent(:read_project_merge_request_analytics)
        prevent(:read_code_review_analytics)
        prevent(:read_issue_analytics)
      end

      rule { ~admin & (~is_gitlab_com & disable_invite_members) }.policy do
        prevent :invite_project_members
        prevent :create_group_link
      end

      rule { ~admin & disable_invite_members_for_group }.policy do
        prevent :invite_project_members
        prevent :create_group_link
      end

      rule { feature_flags_related_issues_disabled | repository_disabled }.policy do
        prevent :admin_feature_flags_issue_links
      end

      rule { monitor_disabled }.policy do
        prevent :read_incident_management_oncall_schedule
        prevent :admin_incident_management_oncall_schedule
        prevent :read_incident_management_escalation_policy
        prevent :create_escalation_policy
        prevent :update_escalation_policy
        prevent :delete_escalation_policy
      end

      rule { ~oncall_schedules_available }.policy do
        prevent :read_incident_management_oncall_schedule
        prevent :admin_incident_management_oncall_schedule
      end

      rule { ~escalation_policies_available }.prevent :read_incident_management_escalation_policy

      rule { can?(:read_code) }.policy do
        enable :read_path_locks
      end

      rule { can?(:push_code) }.policy do
        enable :create_path_lock
      end

      rule { ~iterations_available }.policy do
        prevent :create_iteration
        prevent :admin_iteration
        prevent :read_iteration
      end

      rule { ~custom_roles_allowed }.prevent :read_member_role

      rule { can?(:read_project) & iterations_available }.enable :read_iteration

      rule { ~security_orchestration_policies_enabled }.policy do
        prevent :create_security_policy
        prevent :modify_security_policy
        prevent :read_security_orchestration_policies
        prevent :read_security_orchestration_policy_project
        prevent :update_security_orchestration_policy_project
        prevent :_contribute_security_policy_project
        prevent :force_evaluate_merge_request_security_policy
      end

      rule { ~security_policy_project }.prevent :_contribute_security_policy_project

      rule { can?(:_contribute_security_policy_project) }.policy do
        enable :push_code
        enable :create_merge_request_from
        enable :create_merge_request_in
      end

      rule { direct_security_policy_project_available }.prevent :create_security_policy
      rule { ~can_commit_to_security_policy_project }.prevent :modify_security_policy
      rule { can_commit_to_security_policy_project }.enable :modify_security_policy

      rule { any_security_policy_project_available & ~can_commit_to_any_security_policy_project }.prevent :create_policy_schedule_test_run
      rule { any_security_policy_project_available & can_commit_to_any_security_policy_project }.enable :create_policy_schedule_test_run

      rule { ~security_dashboard_enabled }.policy do
        prevent :create_vulnerability_archive_export
        prevent :create_vulnerability_export
        prevent :create_vulnerability_state_transition
        prevent :admin_vulnerability_external_issue_link
        prevent :admin_vulnerability_issue_link
        prevent :admin_vulnerability_merge_request_link
        prevent :read_project_security_dashboard
        prevent :read_security_project_tracked_ref
        prevent :read_security_resource
        prevent :read_vulnerability
        prevent :admin_vulnerability
        prevent :confirm_vulnerability
        prevent :dismiss_vulnerability
        prevent :_create_dismissal_vulnerability_feedback
        prevent :resolve_vulnerability
        prevent :revert_vulnerability
        prevent :_destroy_dismissal_vulnerability_feedback
        prevent :update_vulnerability_severity
        prevent :read_ascp_component
        prevent :create_ascp_component
        prevent :read_ascp_scan
        prevent :create_ascp_scan
        prevent :update_vulnerability_flag
        prevent :create_security_ai_flow_feedback
        prevent :read_ascp_security_context
        prevent :create_ascp_security_context
        prevent :execute_vulnerability_duo_workflow
      end

      rule { ~security_scans_api_enabled }.policy do
        prevent :access_security_scans_api
      end

      rule { ~coverage_fuzzing_enabled }.policy do
        prevent :read_coverage_fuzzing
        prevent :create_coverage_fuzzing_corpus
      end

      rule { ~security_inventory_available }.prevent :read_security_inventory

      rule { ~on_demand_scans_enabled }.policy do
        prevent :read_on_demand_dast_scan
        prevent :create_on_demand_dast_scan
        prevent :edit_on_demand_dast_scan
        prevent :update_on_demand_dast_scan
      end

      # Security Policy Bot permissions are maintained in YAML:
      # config/authz/roles/security_policy_bot.yml
      #
      # The bot is added as a guest member to the project but we want to restrict
      # its permissions to only what is defined in the YAML role. We use prevent_all
      # to revoke all permissions except those explicitly defined for this bot.
      # This ensures the bot operates with least privilege.
      # TODO: Clean up when bot-membership is properly solved.
      # See: https://gitlab.com/gitlab-org/gitlab/-/issues/594741
      rule { security_policy_bot }.policy do
        enable(*::Authz::Role.get(:security_policy_bot).direct_permissions(:project))
      end

      rule { security_policy_bot }.prevent_all do
        except(*::Authz::Role.get(:security_policy_bot).direct_permissions(:project))
      end

      # Allow security policy bot to pull container images from cross-project registries
      # when the project is in the job token scope. This enables scan execution policies
      # to pull scanner images from a different project's container registry.
      # See: https://gitlab.com/gitlab-org/gitlab/-/issues/630692
      rule { security_policy_bot_via_job_token }.enable :build_read_container_image

      rule { ~security_dashboard_enabled }.prevent :admin_security_testing

      rule { security_dashboard_enabled & can?(:admin_security_testing) }.policy do
        enable :access_security_and_compliance
        enable :admin_vulnerability_merge_request_link
        enable :read_security_configuration
        enable :read_project_security_dashboard
        enable :read_security_resource
        enable :read_vulnerability
        enable :configure_security_scanner
      end

      rule { can?(:configure_security_scanner) }.policy do
        enable :create_merge_request_from
        enable :create_repository_tag
        enable :delete_repository_tag
        enable :download_code
        enable :push_code
        enable :read_merge_request
        enable :update_repository_tag
      end

      rule { secret_push_protection_available & can?(:admin_security_testing) }.policy do
        enable :read_secret_push_protection_info
        enable :enable_secret_push_protection
        enable :read_project_security_exclusions
      end

      rule { ~security_scan_profiles_available }.policy do
        prevent :read_security_scan_profiles
        prevent :apply_security_scan_profiles
        prevent :create_security_scan_profiles
        prevent :update_security_scan_profiles
        prevent :delete_security_scan_profiles
      end

      rule { ~security_attributes_available }.policy do
        prevent :admin_security_attributes
        prevent :read_security_attribute
      end

      rule { ~validity_checks_available }.policy do
        prevent :update_secret_detection_validity_check
        prevent :verify_secret_detection_raw_token
      end

      rule { ~refresh_validity_checks_available }.policy do
        prevent :update_secret_detection_validity_check_status
      end

      rule { coverage_fuzzing_enabled & can?(:admin_security_testing) }.policy do
        enable :read_coverage_fuzzing
        enable :create_coverage_fuzzing_corpus
      end

      rule { security_scans_api_enabled & can?(:admin_security_testing) }.policy do
        enable :access_security_scans_api
      end

      rule { on_demand_scans_enabled & can?(:admin_security_testing) }.policy do
        enable :read_on_demand_dast_scan
        enable :create_on_demand_dast_scan
        enable :edit_on_demand_dast_scan

        enable :read_runners # read runner tags when creating scan
        enable :create_pipeline # run a scan
      end

      # If licensed but not reporter+, prevent access
      rule { can?(:read_merge_request) & can?(:read_issue) & licensed_cycle_analytics_available }.policy do
        enable :read_cycle_analytics
      end

      rule { ~licensed_cycle_analytics_available }.policy do
        prevent :create_value_stream
        prevent :update_value_stream
        prevent :delete_value_stream
      end

      rule { can?(:read_merge_request) & can?(:read_pipeline) }.enable :read_merge_train

      rule { can?(:admin_vulnerability) }.policy do
        enable :read_vulnerability
        enable :create_vulnerability_feedback
        enable :destroy_vulnerability_feedback
        enable :update_vulnerability_feedback
        enable :create_vulnerability_state_transition
        enable :create_security_project_tracked_ref
        enable :delete_security_project_tracked_ref
        enable :update_vulnerability_flag
        enable :execute_vulnerability_duo_workflow
      end

      rule { can?(:read_vulnerability) }.policy do
        enable :read_vulnerability_feedback
        enable :read_vulnerability_scanner
        enable :read_vulnerability_representation_information
        enable :read_vulnerability_statistics
      end

      condition(:resolve_vulnerability_allowed) do
        next false unless @user

        ::Gitlab::Llm::FeatureAuthorizer.new(
          container: subject,
          feature_name: :resolve_vulnerability,
          user: @user
        ).allowed?
      end

      rule { can?(:read_security_resource) & resolve_vulnerability_allowed }.policy do
        enable :resolve_vulnerability_with_ai
      end

      rule { security_bot }.policy do
        enable :admin_merge_request
        enable :create_merge_request_from
        enable :create_repository_tag
        enable :create_vulnerability_feedback
        enable :delete_repository_tag
        enable :push_code
        enable :update_repository_tag
      end

      rule { merge_requests_disabled }.policy do
        prevent :read_project_merge_request_analytics
      end

      rule { issues_disabled & merge_requests_disabled }.policy do
        prevent :read_iteration
        prevent :create_iteration
        prevent :update_iteration
        prevent :admin_iteration
        prevent :destroy_iteration
      end

      rule { ~dependency_scanning_enabled }.prevent :read_dependency, :read_advanced_dependency_management

      rule { ~license_scanning_enabled }.policy do
        prevent :read_licenses
        prevent :read_software_license_policy
      end

      rule { repository_mirrors_enabled & ((mirror_available & can?(:admin_project)) | admin) }.enable :admin_mirror

      rule { ~repository_mirrors_enabled }.prevent :create_pull_mirror

      rule { ~pull_mirror_available & ~admin }.prevent :create_pull_mirror

      rule { ~repository_mirrors_enabled }.prevent :read_pull_mirror

      rule { ~pull_mirror_available & ~admin }.prevent :read_pull_mirror

      rule { ~repository_mirrors_enabled }.prevent :update_pull_mirror

      # Matches admin_remote_mirror, which Repositories::PullMirrors::UpdateService checks
      rule { ~mirror_available & ~admin }.prevent :update_pull_mirror

      rule { ~runner_performance_insights_available }.prevent :read_runner_usage

      rule { ~clickhouse_main_database_available }.prevent :read_runner_usage

      rule { ~license_scanning_enabled }.prevent :admin_software_license_policy

      rule { ~escalation_policies_available }.policy do
        prevent :create_escalation_policy
        prevent :update_escalation_policy
        prevent :delete_escalation_policy
      end

      rule { ~can?(:push_code) }.prevent :push_code_to_protected_branches

      rule { ~push_rules_available }.policy do
        prevent :change_push_rules
      end

      rule { ~commit_committer_check_available }.policy do
        prevent :read_commit_committer_check
        prevent :change_commit_committer_check
      end

      rule { ~commit_committer_name_check_available }.policy do
        prevent :read_commit_committer_name_check
        prevent :change_commit_committer_name_check
      end

      rule { ~reject_unsigned_commits_available }.policy do
        prevent :read_reject_unsigned_commits
        prevent :change_reject_unsigned_commits
      end

      rule { ~reject_non_dco_commits_available }.policy do
        prevent :read_reject_non_dco_commits
        prevent :change_reject_non_dco_commits
      end

      rule { ~admin & owner_cannot_destroy_project }.prevent :remove_project

      rule { user_banned_from_namespace }.prevent_all

      condition(:needs_new_sso_session) do
        ::Gitlab::Auth::GroupSaml::SsoEnforcer.access_restricted?(user: @user, resource: subject)
      end

      condition(:duo_code_review_bot, scope: :user) do
        @user.duo_code_review_bot?
      end

      condition(:ip_enforcement_prevents_access, scope: :subject) do
        !::Gitlab::IpRestriction::Enforcer.new(subject.group).allows_current_ip? if subject.group
      end

      rule { needs_new_sso_session }.policy do
        prevent :read_project
      end

      rule { ip_enforcement_prevents_access & ~admin & ~auditor }.policy do
        prevent_all
      end

      rule { locked_approval_rules & ~admin }.policy do
        prevent :modify_approvers_rules
        prevent :create_approval_rule
        prevent :update_approval_rule
        prevent :delete_approval_rule
      end

      rule { locked_merge_request_author_setting }.policy do
        prevent :modify_merge_request_author_setting
      end

      rule { locked_merge_request_committer_setting }.policy do
        prevent :modify_merge_request_committer_setting
      end

      rule { issue_analytics_enabled }.enable :read_issue_analytics

      rule { ~code_review_analytics_enabled }.prevent :read_code_review_analytics

      rule { ~dora4_analytics_available }.prevent :read_dora4_analytics

      rule { ~project_merge_request_analytics_available }.prevent :read_project_merge_request_analytics

      condition(:assigned_to_duo_enterprise) do
        @user.assigned_to_duo_enterprise?(@subject)
      end

      condition(:assigned_to_duo_pro) do
        @user.assigned_to_duo_pro?(@subject)
      end

      condition(:ai_analytics_available, scope: :subject) do
        @subject.feature_available?(:ai_analytics)
      end

      condition(:amazon_q_enabled, scope: :global) do
        ::Ai::AmazonQ.enabled?
      end

      rule { ~ai_analytics_available }.policy do
        prevent :read_pro_ai_analytics
        prevent :read_enterprise_ai_analytics
      end

      rule { project_level_analytics_dashboard_enabled }.enable :read_project_level_analytics_dashboard

      rule { project_level_analytics_dashboard_enabled & can?(:read_cycle_analytics) }.enable :read_project_level_value_stream_dashboard_overview_counts

      rule { can?(:read_project) & requirements_available }.enable :read_requirement

      rule { ~requirements_available }.policy do
        prevent :create_requirement
        prevent :create_requirement_test_report
        prevent :admin_requirement
        prevent :update_requirement
        prevent :import_requirements
        prevent :export_requirements
      end

      rule { ~requirements_available }.prevent :destroy_requirement

      rule { ~quality_management_available }.prevent :create_test_case

      rule { ~can?(:create_issue) }.policy do
        prevent :create_epic
        prevent :create_test_case
      end

      condition(:can_admin_compliance_framework_in_group) do
        in_group? && can?(:admin_compliance_framework, @subject.group)
      end

      rule { can_admin_compliance_framework_in_group }.enable :admin_compliance_framework

      rule { ~project_epics_available }.prevent :create_epic

      rule { ~project_level_compliance_dashboard_enabled }.policy do
        prevent :read_compliance_dashboard
        prevent :read_agent_artifacts
      end

      rule { ~project_level_compliance_adherence_report_enabled }.policy do
        prevent :read_compliance_adherence_report
      end

      rule { ~project_level_compliance_violations_report_enabled }.policy do
        prevent :read_compliance_violations_report
        prevent :update_compliance_violations_report
      end

      rule { ~status_page_available }.policy do
        prevent :mark_issue_for_publication
        prevent :publish_status_page
        prevent :update_status_page_setting
      end

      rule { ~google_cloud_support_available }.policy do
        prevent :read_runner_cloud_provisioning_info
        prevent :read_runner_gke_provisioning_info
        prevent :provision_cloud_runner
        prevent :provision_gke_runner
        prevent :admin_google_cloud_artifact_registry
        prevent :read_google_cloud_artifact_registry
      end

      rule { hidden }.policy do
        prevent :read_code
        prevent :download_code
        prevent :build_download_code
        prevent :read_protectable_branch
      end

      rule { read_only }.policy do
        prevent(*readonly_abilities)

        readonly_features.each do |feature|
          prevent :"create_#{feature}"
          prevent :"update_#{feature}"
        end

        prevent(*all_job_write_abilities)
      end

      rule { ~group_merge_request_approval_settings_enabled }.policy do
        prevent :read_merge_request_approval_setting
        prevent :update_merge_request_approval_setting
      end

      rule { ~compliance_framework_available }.policy do
        prevent :admin_compliance_framework
      end

      rule { ~project_level_compliance_dashboard_enabled }.policy do
        prevent :read_compliance_dashboard
        prevent :read_agent_artifacts
      end

      rule { ~project_level_compliance_adherence_report_enabled }.policy do
        prevent :read_compliance_adherence_report
      end

      rule { ~project_level_compliance_violations_report_enabled }.policy do
        prevent :read_compliance_violations_report
        prevent :update_compliance_violations_report
      end

      rule { can?(:create_issue) & okrs_enabled }.policy do
        enable :create_objective
        enable :create_key_result
      end

      rule { can?(:manage_merge_request_settings) & target_branch_rules_available }.policy do
        enable :admin_target_branch_rule
      end

      # Dependency Management SA permissions are maintained in YAML:
      # config/authz/roles/dependency_management_service_account.yml
      rule { dependency_management_service_account }.policy do
        enable(*::Authz::Role.get(:dependency_management_service_account).direct_permissions(:project))
      end

      rule do
        summarize_new_merge_request_enabled & can?(:create_merge_request_in)
      end.enable :access_summarize_new_merge_request

      rule do
        generate_description_enabled & can?(:create_issue)
      end.enable :generate_description

      rule do
        summarize_notes_allowed & can?(:read_issue)
      end.enable :summarize_comments

      rule { ~target_branch_rules_available }.prevent :admin_target_branch_rule

      rule { target_branch_rules_available }.policy do
        enable :read_target_branch_rule
      end

      rule { ~pages_multiple_versions_available }.prevent :pages_multiple_versions

      rule { ~observability_enabled }.policy do
        prevent :read_observability
        prevent :write_observability
        prevent :update_observability_alert_setting
      end

      rule { ci_cancellation_maintainers_only & ~can?(:_cancel_restricted_ci) }.policy do
        prevent :cancel_pipeline
        prevent :cancel_build
      end

      rule { ci_cancellation_no_one }.policy do
        prevent :cancel_pipeline
        prevent :cancel_build
      end

      rule { ai_features_banned }.policy do
        prevent :access_duo_classic_chat
        prevent :access_duo_agentic_chat
        prevent :access_code_suggestions
      end

      rule { can?(:read_project) & code_suggestions_enabled_for_user }.enable :access_code_suggestions

      rule { ~code_suggestions_licensed }.prevent :access_code_suggestions
      rule { ~duo_features_enabled }.prevent :access_code_suggestions

      rule { can?(:read_project) & classic_chat_allowed_for_parent_group & classic_chat_available_for_user & duo_features_enabled }.policy do
        enable :access_duo_classic_chat
      end

      rule do
        can?(:read_project) &
          duo_features_enabled &
          duo_agent_platform_enabled &
          agentic_chat_available_for_user &
          agentic_chat_allowed_for_parent_group
      end.enable :access_duo_agentic_chat

      rule { amazon_q_enabled }.policy { prevent :access_duo_agentic_chat }

      rule { ~amazon_q_enabled & ~duo_workflow_available }.policy do
        prevent :manage_ai_flow_triggers
        prevent :read_ai_flow_triggers
        prevent :trigger_ai_flow
      end

      # Flow triggers and their schedules are managed by whoever manages flow triggers;
      # granular permissions exist so enforcement points stay fine-grained.
      rule { can?(:manage_ai_flow_triggers) }.policy do
        enable :create_ai_flow_schedule
        enable :update_ai_flow_schedule
        enable :delete_ai_flow_schedule
        enable :create_ai_flow_trigger
        enable :update_ai_flow_trigger
        enable :delete_ai_flow_trigger
      end

      rule { ~can?(:create_pipeline) }.prevent :trigger_ai_flow

      rule do
        check_customizable_ai_settings &
          below_minimum_access_level_execute
      end.prevent :access_duo_agentic_chat

      condition(:check_customizable_ai_settings) do
        customizable_permissions_enabled? &&
          !can?(:update_organization, @subject.organization)
      end

      condition(:below_minimum_access_level_execute) do
        next false unless @subject.root_ancestor.is_a?(Group)

        minimum_access_level_execute = @subject.root_ancestor.ai_minimum_access_level_execute_with_fallback
        next false if minimum_access_level_execute.nil?

        team_access_level < minimum_access_level_execute
      end

      condition(:ai_settings_prevent_execute_async) do
        customizable_permissions_enabled? &&
          @subject.root_ancestor.is_a?(Group) &&
          !can?(:update_organization, @subject.organization) &&
          team_access_level < @subject.root_ancestor.ai_minimum_access_level_execute_async_with_fallback
      end

      rule { ai_settings_prevent_execute_async }.prevent :trigger_ai_flow

      rule { can?(:read_project) & duo_features_enabled }.enable :access_duo_features

      desc "Code Navigation rollout flag is enabled for the user"
      condition(:code_navigation_flag_enabled, scope: :user, score: 0) do
        ::Feature.enabled?(:orbit_code_intelligence, @user)
      end

      desc "Knowledge Graph is configured on this instance and enabled for the user"
      condition(:knowledge_graph_available, scope: :user) do
        ::Analytics::KnowledgeGraph.enabled_for?(@user)
      end

      desc "Orbit is licensed for this project"
      condition(:orbit_licensed, scope: :subject) do
        ::Analytics::KnowledgeGraph::OrbitLicense.entitled?(@subject)
      end

      desc "The project's root namespace is enrolled in Orbit indexing"
      condition(:knowledge_graph_indexing_enabled, scope: :subject) do
        @subject.knowledge_graph_indexing_enabled?
      end

      rule { ~code_navigation_flag_enabled }.prevent :read_code_navigation
      rule { ~knowledge_graph_available }.prevent :read_code_navigation
      rule { ~orbit_licensed }.prevent :read_code_navigation
      rule { ~knowledge_graph_indexing_enabled }.prevent :read_code_navigation
      rule { ~can?(:read_code) }.prevent :read_code_navigation

      desc "Project has saved replies support"
      condition(:supports_saved_replies, scope: :subject) do
        @subject.supports_saved_replies?
      end

      rule { ~supports_saved_replies }.policy do
        prevent :read_saved_reply
        prevent :create_saved_reply
        prevent :delete_saved_reply
        prevent :update_saved_reply
      end

      condition(:secret_push_protection_available, scope: :subject) do
        @subject.licensed_feature_available?(:secret_push_protection)
      end

      rule { ~secret_push_protection_available }.prevent :enable_secret_push_protection

      condition(:validity_checks_available, scope: :subject) do
        @subject.licensed_feature_available?(:secret_detection_validity_checks)
      end

      condition(:refresh_validity_checks_available, scope: :subject) do
        @subject.licensed_feature_available?(:secret_detection_validity_checks)
      end

      condition(:container_scanning_for_registry_available, scope: :subject) do
        @subject.licensed_feature_available?(:container_scanning_for_registry)
      end
      rule { ~container_scanning_for_registry_available }.policy do
        prevent :enable_container_scanning_for_registry
      end

      condition(:container_scanning_available, scope: :subject) do
        @subject.licensed_feature_available?(:container_scanning)
      end
      condition(:dependency_scanning_available, scope: :subject) do
        @subject.licensed_feature_available?(:dependency_scanning)
      end
      rule { ~container_scanning_available }.policy do
        prevent :update_cvs_for_container_scanning
      end
      rule { ~dependency_scanning_available }.policy do
        prevent :update_cvs_for_dependency_scanning
      end

      condition(:license_information_source_available, scope: :subject) do
        @subject.licensed_feature_available?(:license_information_source)
      end
      rule { ~license_information_source_available }.prevent :set_license_information_source

      condition(:license_scanning_available, scope: :subject) do
        @subject.licensed_feature_available?(:license_scanning)
      end
      rule { ~license_scanning_available }.prevent :toggle_license_scanning_for_cyclonedx

      rule { ~secret_push_protection_available }.prevent :read_secret_push_protection_info

      rule { ~duo_agent_platform_enabled | ~duo_workflow_available }.policy do
        prevent :duo_workflow
        prevent :create_duo_workflow_for_ci
      end

      rule { ~duo_agent_platform_enabled | ~duo_features_enabled }.prevent :create_security_ai_flow_feedback

      rule { ai_settings_prevent_execute_async }.prevent :create_duo_workflow_for_ci

      with_scope :subject
      condition(:duo_otel_workflow_available) do
        !@subject.empty_repo? &&
          @subject.repository_languages.present? &&
          ::Feature.enabled?(:duo_add_otel, @subject, type: :gitlab_com_derisk) &&
          @subject.duo_remote_flows_enabled &&
          @subject.duo_features_enabled &&
          @subject.licensed_ai_features_available? &&
          @subject.duo_foundational_flows_enabled
      end

      rule { duo_otel_workflow_available & can?(:push_code) }.policy do
        enable :create_duo_otel_workflow
      end

      with_scope :subject
      condition(:runner_performance_insights_available) do
        @subject.group&.licensed_feature_available?(:runner_performance_insights_for_namespace)
      end

      with_scope :global
      condition(:clickhouse_main_database_available) do
        ::Gitlab::ClickHouse.configured?
      end

      condition(:container_registry_immutable_tag_rules_available, scope: :subject) do
        @subject.feature_available?(:container_registry_immutable_tag_rules)
      end

      rule { ~container_registry_immutable_tag_rules_available }.prevent :create_container_registry_protection_immutable_tag_rule

      condition(:secrets_manager_enabled, scope: :subject) do
        ::SecretsManagement::Availability.for_project?(@subject)
      end

      rule { ~secrets_manager_enabled }.policy do
        prevent :admin_project_secrets_manager
        prevent :create_project_secrets
        prevent :create_secrets_manager_api_jwt
        prevent :delete_project_secrets
        prevent :provision_secrets_manager
        prevent :read_project_secrets
        prevent :read_project_secrets_manager
        prevent :read_project_secrets_manager_status
        prevent :update_project_secrets
      end

      # Granular tokens read secrets permissions with read_secrets_permission, as on groups.
      # On a project, it follows the ability that lists them.
      rule { can?(:read_project_secrets_manager) }.enable :read_secrets_permission

      condition(:secrets_manager_entitlement_denies_access, score: SECRETS_MANAGER_ENTITLEMENT_SCORE) do
        secrets_manager_enabled? &&
          !secrets_manager_entitlement.permits_read?
      end

      # Narrower than `secrets_manager_entitlement_denies_access`: gates the
      # non-CI/CD REST access-token endpoint, which hands the client a JWT to
      # read straight from OpenBao (the same direct-access pattern CI uses).
      condition(:secrets_manager_entitlement_denies_direct_read, score: SECRETS_MANAGER_ENTITLEMENT_SCORE) do
        secrets_manager_enabled? &&
          !secrets_manager_entitlement.permits_direct_read?
      end

      condition(:secrets_manager_entitlement_denies_writes, score: SECRETS_MANAGER_ENTITLEMENT_SCORE) do
        secrets_manager_enabled? &&
          !secrets_manager_entitlement.permits_writes?
      end

      # Projects stay hidden until the top-level group's entitlement
      # transitions past `trial_eligible`, except for the free-beta cohort,
      # which keeps visibility of the secrets it created during the beta.
      # `beta_window_eligible` is the resolver's realm-aware beta signal
      # (namespace enrollment on SaaS, instance enrollment on self-managed).
      condition(:secrets_manager_entitlement_trial_eligible_on_project, score: SECRETS_MANAGER_ENTITLEMENT_SCORE) do
        secrets_manager_enabled? &&
          secrets_manager_entitlement.state == :trial_eligible &&
          !secrets_manager_entitlement.beta_window_eligible
      end

      rule { secrets_manager_entitlement_denies_access }.policy do
        prevent :read_project_secrets
        prevent :admin_project_secrets_manager
        prevent :provision_secrets_manager
        prevent :create_project_secrets
        prevent :update_project_secrets
        prevent :delete_project_secrets
      end

      rule { secrets_manager_entitlement_denies_direct_read }.prevent :create_secrets_manager_api_jwt

      # Delete is not here on purpose: the billing entitlement only blocks deletes
      # when it blocks reads (`secrets_manager_entitlement_denies_access`). Role
      # and OpenBao ACL checks for delete are unaffected.
      rule { secrets_manager_entitlement_denies_writes }.policy do
        prevent :admin_project_secrets_manager
        prevent :provision_secrets_manager
        prevent :create_project_secrets
        prevent :update_project_secrets
      end

      rule { secrets_manager_entitlement_trial_eligible_on_project }.policy do
        prevent :read_project_secrets
        prevent :delete_project_secrets
        prevent :read_project_secrets_manager
        prevent :read_project_secrets_manager_status
        prevent :create_secrets_manager_api_jwt
      end

      condition(:ai_review_mr_enabled, scope: :subject) do
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

      rule { duo_workflow_token & ~duo_features_enabled }.prevent_all

      condition(:ai_catalog_available, scope: :subject) do
        ::Ai::Catalog.available_for_project?(@subject)
      end

      condition(:ai_catalog_available_for_user) do
        # This checks only applies to when user is not anonymous
        @user.nil? || @user.allowed_to_use_through_namespace?(:ai_catalog, @subject.root_ancestor)
      end

      condition(:provision_ai_catalog_allowed, scope: :subject) do
        ::Ai::Catalog.provisioning_available?(@subject)
      end

      condition(:foundational_flows_available, scope: :subject) do
        @subject.foundational_flows_available?
      end

      condition(:flows_available, scope: :subject) do
        ::Gitlab::Llm::StageCheck.available?(@subject, :ai_catalog_flows)
      end

      condition(:ai_catalog_skills_enabled, scope: :subject) do
        ::Feature.enabled?(:ai_catalog_skills, @subject)
      end

      condition(:third_party_flows_enabled, scope: :user) do
        ::Feature.enabled?(:ai_catalog_third_party_flows, @user)
      end

      condition(:create_third_party_flows_enabled, scope: :user) do
        ::Feature.enabled?(:ai_catalog_create_third_party_flows, @user)
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

      rule { ~ai_catalog_available | ~ai_catalog_available_for_user }.policy do
        prevent :create_ai_catalog_flow
        prevent :read_ai_catalog_flow
        prevent :create_ai_catalog_third_party_flow
        prevent :read_ai_catalog_third_party_flow
        prevent :execute_ai_catalog_item
        prevent :admin_ai_catalog_item
        prevent :admin_ai_catalog_item_consumer
        prevent :create_ai_catalog_flow_item_consumer
        prevent :create_ai_catalog_third_party_flow_item_consumer
        prevent :read_ai_catalog_item_consumer
        prevent :create_ai_catalog_agent
        prevent :create_ai_catalog_agent_item_consumer
        prevent :create_ai_catalog_skill_item_consumer
      end

      rule { ~provision_ai_catalog_allowed }.policy do
        prevent :provision_ai_catalog
        prevent :create_ai_catalog_item_consumer
      end

      rule { ~flows_available }.policy do
        prevent :create_ai_catalog_flow
        prevent :read_ai_catalog_flow
        prevent :create_ai_catalog_flow_item_consumer
      end

      rule { ~duo_custom_flows_enabled }.policy do
        prevent :create_ai_catalog_flow
        prevent :create_ai_catalog_flow_item_consumer
      end

      rule { ~duo_custom_agents_enabled }.policy do
        prevent :create_ai_catalog_agent
        prevent :create_ai_catalog_agent_item_consumer
      end

      rule { ~ai_catalog_skills_enabled }.prevent :create_ai_catalog_skill_item_consumer

      rule { ~foundational_flows_available | ~ai_catalog_available_for_user }.policy do
        prevent :read_ai_foundational_flow
        prevent :create_ai_foundational_flow_item_consumer
      end

      rule { ~third_party_flows_enabled | ~third_party_flows_available }.policy do
        prevent :create_ai_catalog_third_party_flow
        prevent :read_ai_catalog_third_party_flow
        prevent :create_ai_catalog_third_party_flow_item_consumer
      end

      rule { ~create_third_party_flows_enabled }.policy do
        prevent :create_ai_catalog_third_party_flow
      end

      condition(:duo_external_agents_enabled, scope: :subject) do
        @subject.root_ancestor.duo_external_agents_enabled
      end

      rule { ~duo_external_agents_enabled }.policy do
        prevent :create_ai_catalog_third_party_flow
        prevent :create_ai_catalog_third_party_flow_item_consumer
      end

      condition(:ai_governance_session_gate, scope: :subject) do
        ::Feature.enabled?(:ai_governance_session_gate, @subject.root_ancestor)
      end

      condition(:ai_governance_enabled, scope: :subject) do
        ::Ai::Governance::AgentGovernance.enabled_for?(@subject)
      end

      rule { ~ai_governance_session_gate & ~duo_external_agents_enabled }.policy do
        prevent :create_ai_agent_identity
        prevent :create_ai_agent_session
        prevent :create_ai_agent_audit_event
        prevent :update_ai_agent_session
        prevent :read_ai_agent_session
      end

      rule { ai_governance_session_gate & ~ai_governance_enabled }.policy do
        prevent :create_ai_agent_identity
        prevent :create_ai_agent_session
        prevent :create_ai_agent_audit_event
        prevent :update_ai_agent_session
        prevent :read_ai_agent_session
      end

      rule { container_registry_disabled }.policy do
        prevent :create_container_registry_protection_immutable_tag_rule
      end

      condition(:contribution_analytics_available, scope: :subject) do
        @subject.feature_available?(:contribution_analytics)
      end

      rule { ~contribution_analytics_available }.prevent :read_contribution_analytics

      desc "Project content is read-only while GitHub updates are on"
      condition(:import_sync_read_only, scope: :subject) do
        ::Import::Sync::Projects::WritePolicy.read_only?(project)
      end

      rule { import_sync_read_only }.policy do
        prevent :admin_issue
        prevent :admin_issue_link
        prevent :admin_label
        prevent :admin_merge_request
        prevent :admin_milestone
        prevent :admin_note
        prevent :admin_remote_mirror
        prevent :admin_upload
        prevent :approve_merge_request
        prevent :create_incident
        prevent :create_issue
        prevent :create_issue_link
        prevent :create_label
        prevent :create_merge_request
        prevent :create_merge_request_from
        prevent :create_merge_request_in
        prevent :create_merge_request_review
        prevent :create_milestone
        prevent :create_note
        prevent :create_release
        prevent :create_repository_tag
        prevent :create_test_case
        prevent :delete_label
        prevent :delete_milestone
        prevent :delete_note
        prevent :delete_repository_tag
        prevent :destroy_issue
        prevent :destroy_issue_link
        prevent :destroy_merge_request
        prevent :destroy_release
        prevent :destroy_upload
        prevent :promote_milestone
        prevent :push_code
        prevent :push_code_to_protected_branches
        prevent :push_to_delete_protected_branch
        prevent :reopen_issue
        prevent :reopen_merge_request
        prevent :resolve_note
        prevent :rewrite_repository_history
        prevent :update_issue
        prevent :update_issue_link
        prevent :update_label
        prevent :update_merge_request
        prevent :update_milestone
        prevent :update_note
        prevent :update_release
        prevent :update_repository_tag
        prevent :upload_file
      end
    end

    override :lookup_access_level!
    def lookup_access_level!
      return ::Gitlab::Access::NO_ACCESS if needs_new_sso_session?
      return ::Gitlab::Access::REPORTER if security_bot?
      return ::Gitlab::Access::DEVELOPER if duo_code_review_bot?

      super
    end

    # Available in Core for self-managed but only paid for .com to prevent abuse
    override :resource_access_token_create_feature_available?
    def resource_access_token_create_feature_available?
      return false unless resource_access_token_feature_available?
      return super unless ::Gitlab.com?

      namespace = project.namespace
      namespace.licensed_feature_available?(:resource_access_token)
    end

    override :container_registry_access_allowed?
    def container_registry_access_allowed?
      return true if super
      return false unless project.project_feature&.private?(:container_registry)
      return false unless project_allowed_for_job_token_by_scope?

      custom_role_enables_pull_container_image?
    end

    override :resource_access_token_feature_available?
    def resource_access_token_feature_available?
      return false if ::Gitlab::CurrentSettings.personal_access_tokens_disabled?

      super
    end

    def in_group?
      project&.namespace&.group_namespace?
    end

    def secrets_manager_entitlement
      strong_memoize_with(:secrets_manager_entitlement, subject, user) do
        root = subject.root_ancestor
        ::SecretsManagement::Entitlement.for(root.is_a?(::Group) ? root : nil, user: user)
      end
    end

    def custom_role_ability(user, subject)
      strong_memoize_with(:custom_role_ability, user, subject) do
        ::Authz::CustomAbility.new(user, subject)
      end
    end

    def all_security_policy_configurations
      strong_memoize_with(:all_security_policy_configurations, subject) do
        subject.all_security_orchestration_policy_configurations(include_invalid: true)
      end
    end

    def customizable_permissions_enabled?
      if is_gitlab_com?
        ::Feature.enabled?(:dap_group_customizable_permissions, project.root_ancestor)
      else
        ::Feature.enabled?(:dap_instance_customizable_permissions, :instance)
      end
    end
  end
end
