# frozen_string_literal: true

module Security
  module Policies
    class ProjectTransferWorker
      include ApplicationWorker
      include Gitlab::Utils::StrongMemoize

      data_consistency :sticky
      idempotent!
      deduplicate :until_executed

      concurrency_limit -> { 200 }

      feature_category :security_policy_management

      def perform(project_id, current_user_id, old_namespace_id, _)
        project = Project.find_by_id(project_id)

        return unless project
        return unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)

        current_user = User.find_by_id(current_user_id)
        old_namespace = Namespace.find_by_id(old_namespace_id)

        unassign_project_policy_configuration(project, current_user)
        delete_security_policy_project_links(project)
        delete_approval_rules(old_namespace, project)

        create_security_policy_bot(project, current_user)
        sync_new_namespace_policies(project)
      end

      private

      def unassign_project_policy_configuration(project, current_user)
        return unless current_user && project.security_orchestration_policy_configuration

        ::Security::Orchestration::UnassignService.new(container: project, current_user: current_user)
          .execute(delete_bot: false)

        security_policy_bot = project.security_policy_bot
        return if security_policy_bot.nil?

        Users::DestroyService.new(current_user)
          .execute(security_policy_bot, hard_delete: false, skip_authorization: true)
      end

      def delete_security_policy_project_links(project)
        project.security_policy_project_links.each_batch { |relation| relation.delete_all }
        project.approval_policy_rule_project_links.each_batch { |relation| relation.delete_all }
        # Group-inherited policies stop applying once the project leaves the group, but that group's
        # config is never re-synced against this project, so its schedules must be cleaned up explicitly.
        Security::PipelineExecutionProjectSchedule.for_project(project).each_batch { |relation| relation.delete_all }
        Security::ScanExecutionProjectSchedule.for_project(project).each_batch { |relation| relation.delete_all }
      end

      def delete_approval_rules(old_namespace, project)
        delete_rules_for_configurations(all_policy_configurations(project), project)
        delete_rules_for_configurations(all_policy_configurations(old_namespace), project) if old_namespace
        return unless Feature.enabled?(:cleanup_inapplicable_policy_approval_rules, project)

        # Rules of a configuration outside both hierarchies, e.g. left by an earlier transfer, still enforce.
        delete_rules_for_configurations(
          Security::OrchestrationPolicyConfiguration.with_scan_result_policy_rules_for_project(project), project
        )
      end

      def delete_rules_for_configurations(configurations, project)
        configurations.each do |configuration|
          configuration.delete_scan_result_policy_rules_for_project(project)
        end
      end

      def sync_new_namespace_policies(project)
        all_policy_configurations(project).each do |configuration|
          ::Security::SyncProjectPoliciesWorker.perform_async(project.id, configuration.id)
        end
      end

      def create_security_policy_bot(project, current_user)
        return unless current_user && all_policy_configurations(project).any?

        ::Security::Orchestration::CreateBotService.new(project, current_user).execute
      end

      def all_policy_configurations(container)
        strong_memoize_with(:all_policy_configurations, container) do
          container.all_security_orchestration_policy_configurations(include_invalid: true)
        end
      end
    end
  end
end
