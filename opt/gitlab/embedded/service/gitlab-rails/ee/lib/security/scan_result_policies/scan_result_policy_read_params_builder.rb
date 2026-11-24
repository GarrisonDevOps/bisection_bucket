# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class ScanResultPolicyReadParamsBuilder
      def initialize(project:, security_policy:, approval_policy_rule:, action_index:, approval_action:)
        @project = project
        @security_policy = security_policy
        @approval_policy_rule = approval_policy_rule
        @action_index = action_index
        @approval_action = approval_action
      end

      def build
        rule_content = approval_policy_rule.content.deep_symbolize_keys

        send_bot_message_action = security_policy.policy_content[:actions]&.find do |action|
          action[:type] == Security::ScanResultPolicy::SEND_BOT_MESSAGE
        end

        {
          orchestration_policy_idx: security_policy.policy_index,
          rule_idx: approval_policy_rule.rule_index,
          action_idx: action_index,
          license_states: rule_content[:license_states],
          licenses: rule_content[:licenses] || {},
          match_on_inclusion_license: rule_content[:match_on_inclusion_license] || false,
          role_approvers: role_access_levels(approval_action&.dig(:role_approvers)),
          custom_roles: custom_role_approvers(approval_action&.dig(:role_approvers)),
          vulnerability_attributes: rule_content[:vulnerability_attributes],
          project_id: project.id,
          age_operator: rule_content.dig(:vulnerability_age, :operator),
          age_interval: rule_content.dig(:vulnerability_age, :interval),
          age_value: rule_content.dig(:vulnerability_age, :value),
          commits: rule_content[:commits],
          project_approval_settings: security_policy.policy_content.fetch(:approval_settings, {}),
          send_bot_message: send_bot_message_action&.slice(:enabled, :visibility) || {},
          fallback_behavior: security_policy.policy_content.fetch(:fallback_behavior, {}),
          policy_tuning: security_policy.policy_content.fetch(:policy_tuning, {}),
          approval_policy_rule_id: approval_policy_rule.id,
          malicious_rule: malicious_rule?(rule_content)
        }
      end

      private

      attr_reader :project, :security_policy, :approval_policy_rule, :action_index, :approval_action

      def role_access_levels(role_approvers)
        return [] unless role_approvers

        roles_map = Gitlab::Access.sym_options_with_owner
        role_approvers
          .filter_map { |role| roles_map[role.to_sym] if role.to_s.in?(Security::ScanResultPolicy::ALLOWED_ROLES) }
      end

      def custom_role_approvers(role_approvers)
        return [] unless role_approvers

        role_approvers.select { |role| role.is_a?(Integer) }
      end

      def malicious_rule?(rule_content)
        scanners = rule_content[:scanners]
        return false unless scanners.is_a?(Array)

        scanners.any? { |scanner| scanner.is_a?(Hash) && scanner[:is_malicious] == true }
      end
    end
  end
end
