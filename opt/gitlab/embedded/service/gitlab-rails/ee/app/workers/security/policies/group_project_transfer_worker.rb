# frozen_string_literal: true

module Security
  module Policies
    class GroupProjectTransferWorker
      include ApplicationWorker
      include Gitlab::Utils::StrongMemoize

      data_consistency :sticky
      idempotent!
      deduplicate :until_executed

      concurrency_limit -> { 200 }
      concurrency_limit_scope :root_namespace, max_percentage: 0.25,
        enabled: -> {
          Feature.enabled?(:group_project_transfer_worker_concurrency_limit_scope, :instance)
        }

      feature_category :security_policy_management

      def perform(project_id, current_user_id)
        @project = Project.find_by_id(project_id) || return
        @current_user = User.find_by_id(current_user_id) || return

        security_policies_to_link.each do |policy|
          execute_change(policy, :link)
        end

        security_policies_to_unlink.each do |policy|
          execute_change(policy, :unlink)
        end

        if Feature.enabled?(:cleanup_inapplicable_policy_approval_rules, project)
          delete_rules_of_inapplicable_configurations
        end

        remove_security_policy_bot if should_remove_security_policy_bot?
      end

      private

      attr_reader :project, :current_user

      def security_policies_to_unlink
        Security::Policy.for_policy_configuration(policy_configuration_ids_to_unlink)
      end

      def security_policies_to_link
        Security::Policy.for_policy_configuration(policy_configuration_ids_to_link)
      end

      def policy_configuration_ids_to_unlink
        current_group_security_policy_configuration_ids - desired_group_policy_configuration_ids
      end

      def policy_configuration_ids_to_link
        desired_group_policy_configuration_ids - current_group_security_policy_configuration_ids
      end

      def desired_group_policy_configuration_ids
        project
          .all_security_orchestration_policy_configurations(include_invalid: true)
          .filter(&:namespace_id)
          .pluck(:id) # rubocop:disable CodeReuse/ActiveRecord -- false positive as this is Array#pluck
      end
      strong_memoize_attr :desired_group_policy_configuration_ids

      def current_group_security_policy_configuration_ids
        # rubocop:disable CodeReuse/ActiveRecord -- database access
        project
          .security_policies
          .joins(:security_orchestration_policy_configuration)
          .merge(Security::OrchestrationPolicyConfiguration.for_project(nil))
          .pluck(:security_orchestration_policy_configuration_id)
        # rubocop:enable CodeReuse/ActiveRecord
      end
      strong_memoize_attr :current_group_security_policy_configuration_ids

      def execute_change(policy, action)
        Security::SecurityOrchestrationPolicies::LinkProjectService.new(
          project: project,
          security_policy: policy,
          action: action
        ).execute
      end

      # Unlinking only reaches configurations the project still has links to. Rules can outlive their
      # links (e.g. after an older transfer), and nothing else removes them.
      def delete_rules_of_inapplicable_configurations
        applicable_ids = project.all_security_orchestration_policy_configurations(include_invalid: true).map(&:id)

        Security::OrchestrationPolicyConfiguration
          .with_scan_result_policy_rules_for_project(project)
          .id_not_in(applicable_ids)
          .each { |configuration| configuration.delete_scan_result_policy_rules_for_project(project) }
      end

      def should_remove_security_policy_bot?
        project.all_security_orchestration_policy_configurations(include_invalid: true).empty?
      end

      def remove_security_policy_bot
        Security::OrchestrationConfigurationRemoveBotWorker.perform_async(project.id, current_user.id)
      end
    end
  end
end
