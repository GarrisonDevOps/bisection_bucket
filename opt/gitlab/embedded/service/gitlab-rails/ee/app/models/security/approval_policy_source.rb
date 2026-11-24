# frozen_string_literal: true

module Security
  # TODO: Remove this adapter once `Security::ScanResultPolicyRead` is dropped
  # (https://gitlab.com/gitlab-org/gitlab/-/work_items/617802). Callers should
  # then interact with `Security::ApprovalPolicyRule` directly. Until then,
  # approval rules with a NULL approval_policy_rule_id still exist in production,
  # so scan_result_policy_read remains the fallback source for them.
  class ApprovalPolicySource
    include ::Gitlab::Utils::StrongMemoize

    DELEGATED_METHODS = %i[
      fail_open?
      newly_detected?
      only_newly_detected_licenses?
      bot_message_disabled?
      unblock_rules_using_execution_policies?
      vulnerability_age
      vulnerability_attributes
      commits_any?
      commits_unsigned?
      prevent_approval_by_author?
      prevent_approval_by_commit_author?
      match_on_inclusion_license
    ].freeze

    delegate(*DELEGATED_METHODS, to: :delegation_target, allow_nil: true)

    def initialize(project:, action_idx:, scan_result_policy_read: nil, approval_policy_rule: nil)
      @project = project
      @action_idx = action_idx
      @scan_result_policy_read = scan_result_policy_read
      @approval_policy_rule = approval_policy_rule
    end

    def has_source?
      delegation_target.present?
    end

    def resolved_approval_policy_rule
      approval_policy_rule || scan_result_policy_read&.approval_policy_rule
    end
    strong_memoize_attr :resolved_approval_policy_rule

    def scan_result_policy_id
      scan_result_policy_read&.id
    end

    def approval_policy_rule_id
      approval_policy_rule&.id
    end

    def id
      delegation_target&.id
    end

    delegate :orchestration_policy_idx, :rule_idx, to: :scan_result_policy_read, allow_nil: true

    def role_approvers
      if approval_policy_rule
        approval_policy_rule.role_approvers(action_idx: action_idx)
      else
        scan_result_policy_read&.role_approvers || []
      end
    end
    strong_memoize_attr :role_approvers

    def custom_roles
      if approval_policy_rule
        approval_policy_rule.custom_roles(action_idx: action_idx)
      else
        scan_result_policy_read&.custom_roles || []
      end
    end
    strong_memoize_attr :custom_roles

    def custom_role_ids_with_permission
      if approval_policy_rule
        approval_policy_rule.custom_role_ids_with_permission(project: project, action_idx: action_idx)
      else
        scan_result_policy_read&.custom_role_ids_with_permission || []
      end
    end

    def license_states
      delegation_target&.license_states || []
    end

    def licenses
      delegation_target&.licenses || {}
    end

    def policy_name(rule_name)
      resolved_approval_policy_rule&.security_policy&.name || rule_name.gsub(/\s\d+\z/, '')
    end

    def warn_mode_policy?
      resolved_approval_policy_rule&.security_policy&.warn_mode? || false
    end

    def security_report_time_window
      resolved_approval_policy_rule&.security_policy&.security_report_time_window
    end

    def scanner_configurations
      resolved_rule = resolved_approval_policy_rule
      return unless resolved_rule&.type_scan_finding?

      rule_obj = resolved_rule.rule
      dependency_filters = Feature.enabled?(:approval_policy_dependency_scanning_filters, project)
      return unless rule_obj.has_scanner_overrides?(dependency_filters: dependency_filters)

      configs = rule_obj.scanner_configurations.map(&:to_h)
      return configs if dependency_filters

      configs.map { |config| config.except(*ScanResultPolicies::Rule::DEPENDENCY_FILTER_ATTRIBUTES) }
    end

    private

    attr_reader :project, :scan_result_policy_read, :approval_policy_rule, :action_idx

    def delegation_target
      approval_policy_rule || scan_result_policy_read
    end
  end
end
