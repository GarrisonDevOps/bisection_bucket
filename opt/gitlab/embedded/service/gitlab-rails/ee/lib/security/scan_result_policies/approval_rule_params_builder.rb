# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class ApprovalRuleParamsBuilder
      REPORT_TYPE_MAPPING = {
        Security::ScanResultPolicy::LICENSE_FINDING => :license_scanning,
        Security::ScanResultPolicy::ANY_MERGE_REQUEST => :any_merge_request
      }.freeze

      def initialize(
        project:, security_policy:, approval_policy_rule:, scan_result_policy_read:,
        approval_action:, action_index:, protected_branch_ids:, author:
      )
        @project = project
        @security_policy = security_policy
        @approval_policy_rule = approval_policy_rule
        @scan_result_policy_read = scan_result_policy_read
        @approval_action = approval_action
        @action_index = action_index
        @protected_branch_ids = protected_branch_ids
        @author = author
      end

      def build
        policy_configuration_id = security_policy.security_orchestration_policy_configuration_id
        rule_params = {
          skip_authorization: true,
          approvals_required: approval_action&.dig(:approvals_required) || 0,
          name: rule_name,
          protected_branch_ids: protected_branch_ids,
          applies_to_all_protected_branches: applies_to_all_protected_branches?,
          rule_type: :report_approver,
          user_ids: users_ids(approval_action&.dig(:user_approvers_ids), approval_action&.dig(:user_approvers)),
          report_type: report_type,
          orchestration_policy_idx: security_policy.policy_index,
          group_ids: groups_ids(approval_action&.dig(:group_approvers_ids), approval_action&.dig(:group_approvers)),
          security_orchestration_policy_configuration_id: policy_configuration_id,
          approval_policy_rule_id: approval_policy_rule.id,
          scan_result_policy_id: scan_result_policy_read&.id,
          approval_policy_action_idx: action_index,
          permit_inaccessible_groups: true
        }

        rule_params[:severity_levels] = [] if approval_policy_rule.type_license_finding?

        if approval_policy_rule.type_scan_finding?
          rule = approval_policy_rule.rule

          rule_params.merge!({
            scanners: rule.scanner_configurations.map(&:type).uniq,
            severity_levels: rule.severity_levels,
            vulnerabilities_allowed: rule.vulnerabilities_allowed,
            vulnerability_states: rule.vulnerability_states
          })
        end

        rule_params
      end

      private

      attr_reader :project, :security_policy, :approval_policy_rule,
        :scan_result_policy_read, :approval_action, :action_index, :protected_branch_ids, :author

      def rule_name
        rule_index = approval_policy_rule.rule_index
        policy_name = security_policy.name
        return policy_name if rule_index == 0

        "#{policy_name} #{rule_index + 1}"
      end

      def applies_to_all_protected_branches?
        approval_policy_rule.rule.applies_to_all_protected_branches?
      end

      def users_ids(user_ids, user_names)
        project.team.users.get_ids_by_ids_or_usernames(user_ids, user_names)
      end

      def groups_ids(group_ids, group_paths)
        Security::ApprovalGroupsFinder.new(group_ids: group_ids,
          group_paths: group_paths,
          user: author,
          container: project.namespace,
          search_globally: search_groups_globally?).execute(include_inaccessible: true)
      end

      def search_groups_globally?
        Gitlab::CurrentSettings.security_policy_global_group_approvers_enabled?
      end

      def report_type
        REPORT_TYPE_MAPPING.fetch(approval_policy_rule.type, :scan_finding)
      end
    end
  end
end
