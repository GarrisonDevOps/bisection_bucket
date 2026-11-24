# frozen_string_literal: true

module EE
  module Projects
    module CreateService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      AUDIT_EVENT_TYPE = 'project_created'
      AUDIT_EVENT_MESSAGE = 'Added project'

      # Cascade workers fire on parent updates, not project creation. New projects
      # get the DB default instead of inheriting from the parent group. Add new
      # write-cascade settings with NOT NULL DEFAULT here.
      DUO_CASCADING_SETTINGS = %i[
        duo_features_enabled
        ai_audit_events_storage_enabled
        ai_governance_enabled
        duo_auto_mode_enabled
        ai_agent_governance_enforcement
        duo_scheduled_triggers_enabled
        duo_code_review_depth_allowed
        duo_code_review_default_depth
      ].freeze

      attr_reader :security_policy_target_project_id, :security_policy_target_namespace_id

      override :initialize
      def initialize(user, params)
        super

        @security_policy_target_project_id = @params.delete(:security_policy_target_project_id)
        @security_policy_target_namespace_id = @params.delete(:security_policy_target_namespace_id)

        @mirror = ::Gitlab::Utils.to_boolean(@params.delete(:mirror), default: false)
        @mirror_trigger_builds = ::Gitlab::Utils.to_boolean(@params.delete(:mirror_trigger_builds), default: false)
      end

      override :execute
      def execute
        remove_unallowed_params

        if create_from_template?
          return ::Projects::CreateFromTemplateService.new(current_user, params).execute
        end

        params.delete(:use_custom_template)

        ci_cd_only = ::Gitlab::Utils.to_boolean(params.delete(:ci_cd_only))
        group_with_project_templates_id = params.delete(:group_with_project_templates_id) if params[:template_name].blank? && params[:template_project_id].blank?

        project = super do |project|
          limit = params.delete(:repository_size_limit)
          # Repository size limit comes as MB from the view
          project.repository_size_limit = ::Gitlab::Utils.try_megabytes_to_bytes(limit) if limit

          validate_namespace_used_with_template(project, group_with_project_templates_id)
        end

        if project&.persisted?
          setup_ci_cd_project if ci_cd_only

          log_audit_event(project)
        end

        project
      end

      private

      def create_from_template?
        super || ::Gitlab::Utils.to_boolean(params[:use_custom_template])
      end

      attr_reader :mirror, :mirror_trigger_builds

      def remove_unallowed_params
        params.delete(:repository_size_limit) unless current_user&.can_admin_all_resources?
      end

      override :after_create_actions
      def after_create_actions
        super do
          create_security_policy_configuration_if_exists
        end

        create_predefined_push_rule if ::Feature.disabled?(:inherited_push_rule_for_project, project)
        set_default_compliance_framework
        setup_pull_mirroring

        return unless project.group

        sync_duo_cascading_defaults_from_namespace
        run_compliance_standards_checks
        sync_group_scan_result_policies
        create_security_policy_project_bot
        sync_foundational_flows_from_namespace
        sync_inherited_service_accounts
        seed_work_item_type_visibility_defaults
      end

      def sync_inherited_service_accounts
        root = project.root_ancestor
        return unless ::Feature.enabled?(:ai_catalog_group_inherited_consumers, root)
        return unless ::Ai::Catalog::ItemConsumer.inherited_with_service_account_for(root).exists?

        ::Ai::Catalog::ItemConsumers::SyncProjectServiceAccountsWorker.perform_async(current_user.id, [project.id])
      end

      def seed_work_item_type_visibility_defaults
        ::WorkItems::TypesFramework::SeedVisibilityDefaultsService.new(project.project_namespace).execute
      end

      def setup_pull_mirroring
        if mirror && can?(current_user, :admin_mirror, project)
          project.update!(
            mirror: mirror,
            mirror_trigger_builds: mirror_trigger_builds,
            mirror_user_id: current_user.id
          )
        end
      end

      override :execute_hooks
      def execute_hooks
        super
        return unless project.has_active_hooks?(:project_hooks)

        hook_data = ::Gitlab::HookData::ProjectBuilder.new(project).build(:create)
        project.execute_hooks(hook_data, :project_hooks)
      end

      def create_security_policy_configuration_if_exists
        return if security_policy_target.blank?

        ::Security::Orchestration::AssignService
            .new(container: security_policy_target, current_user: current_user, params: { policy_project_id: project.id })
            .execute
      end

      def security_policy_target
        if security_policy_target_project_id.present?
          ::Project.find_by_id(security_policy_target_project_id)
        elsif security_policy_target_namespace_id.present?
          ::Namespace.find_by_id(security_policy_target_namespace_id)
        end
      end
      strong_memoize_attr :security_policy_target

      def sync_group_scan_result_policies
        configurations = group_security_orchestration_policy_configurations

        configurations.each do |configuration|
          ::Security::SyncProjectPoliciesWorker.perform_in(1.second, project.id, configuration.id)
        end
      end

      def create_security_policy_project_bot
        return unless group_security_orchestration_policy_configurations.any?

        ::Security::OrchestrationConfigurationCreateBotWorker.perform_in(1.second, project.id, current_user.id)
      end

      def group_security_orchestration_policy_configurations
        project.group.all_security_orchestration_policy_configurations
      end
      strong_memoize_attr :group_security_orchestration_policy_configurations

      # rubocop: disable CodeReuse/ActiveRecord
      def create_predefined_push_rule
        PushRules::CreatePredefinedRuleService
          .new(container: project)
          .execute(override_push_rule: security_policy_target.present?)
      end

      def set_default_compliance_framework
        return unless project.group

        return unless project.licensed_feature_available?(:custom_compliance_frameworks)

        default_compliance_framework_id = project.root_namespace.namespace_settings.default_compliance_framework_id

        return if default_compliance_framework_id.blank?

        user_id = current_user.id

        project.run_after_commit_or_now do
          ::ComplianceManagement::UpdateDefaultFrameworkWorker.perform_async(
            user_id,
            id,
            default_compliance_framework_id
          )
        end
      end

      def run_compliance_standards_checks
        ::ComplianceManagement::Standards::Gitlab::PreventApprovalByAuthorWorker
          .perform_async({ 'project_id' => project.id, 'user_id' => current_user.id })

        ::ComplianceManagement::Standards::Gitlab::PreventApprovalByCommitterWorker
          .perform_async({ 'project_id' => project.id, 'user_id' => current_user.id })

        ::ComplianceManagement::Standards::Gitlab::AtLeastTwoApprovalsWorker
          .perform_async({ 'project_id' => project.id, 'user_id' => current_user.id })

        ::ComplianceManagement::Standards::Soc2::AtLeastOneNonAuthorApprovalWorker
          .perform_async({ 'project_id' => project.id, 'user_id' => current_user.id })
      end

      # When using a project template from a Group, the new project can only be created
      # under the template owner's group or subgroups
      def validate_namespace_used_with_template(project, group_with_project_templates_id)
        return unless project.group

        subgroup_with_templates_id = group_with_project_templates_id || params[:group_with_project_templates_id]
        return if subgroup_with_templates_id.blank?

        templates_owner = ::Group.find(subgroup_with_templates_id).parent

        unless templates_owner.self_and_descendants.exists?(id: project.namespace_id)
          project.errors.add(:namespace, _("is not a descendant of the Group owning the template"))
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def setup_ci_cd_project
        return unless ::License.feature_available?(:ci_cd_projects)

        ::CiCd::SetupProject.new(project, current_user).execute
      end

      def log_audit_event(project)
        audit_context = {
          name: AUDIT_EVENT_TYPE,
          author: current_user,
          scope: project,
          target: project,
          message: AUDIT_EVENT_MESSAGE,
          target_details: project.full_path
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def sync_duo_cascading_defaults_from_namespace
        DUO_CASCADING_SETTINGS.each do |setting|
          db_default = ::ProjectSetting.column_defaults[setting.to_s]

          inherited_value = project.group.public_send(setting) # rubocop:disable GitlabSecurity/PublicSend -- setting names from a frozen constant
          next if inherited_value == db_default

          next if project.project_setting.public_send(:"#{setting}_locked?") # rubocop:disable GitlabSecurity/PublicSend -- setting names from a frozen constant

          project.project_setting.update!(setting => inherited_value)
        end
      end

      # Individual flow failures remain non-fatal to project creation.
      def sync_foundational_flows_from_namespace
        return unless project.duo_foundational_flows_enabled

        cascaded_target_catalog_item_ids = project.enabled_flow_catalog_item_ids
        project.sync_enabled_foundational_flows!(cascaded_target_catalog_item_ids)

        ::Ai::Catalog::Flows::SyncFoundationalFlowsService.new(
          project,
          current_user: current_user,
          provisioning_mode: :inherited_project
        ).execute
      end
    end
  end
end
