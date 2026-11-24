# frozen_string_literal: true

module EE
  module ResolvesMergeRequests
    extend ActiveSupport::Concern

    private

    def preloads
      super.tap do |h|
        h[:ai_suggested_reviewers] = [
          :reviewers, :scan_result_policy_violations, :security_policies_through_violations,
          { ai_suggested_reviewers: [:user, :approval_merge_request_rule, :approval_project_rule] }
        ]
        h[:change_requesters] = [:change_requesters]
        h[:approved] = [*approved_mergeability_check_preloads, *security_policy_violation_check_preloads]
        h[:approval_state] = approved_mergeability_check_preloads

        h[:mergeable] += [
          *approved_mergeability_check_preloads,
          *blocked_by_other_mrs_mergeability_check_preloads,
          *commits_status_mergeability_check_preloads,
          *security_policy_violation_check_preloads
        ]

        h[:detailed_merge_status] += [
          *approved_mergeability_check_preloads,
          *blocked_by_other_mrs_mergeability_check_preloads,
          *commits_status_mergeability_check_preloads,
          *security_policy_violation_check_preloads
        ]

        h[:mergeability_checks] += [
          *approved_mergeability_check_preloads,
          *blocked_by_other_mrs_mergeability_check_preloads,
          *commits_status_mergeability_check_preloads,
          *security_policy_violation_check_preloads,
          { target_project: [:security_policy_management_project_linked_configurations] },
          :blocking_merge_requests,
          :requested_changes,
          :failed_scan_result_policy_violations,
          { target_project: [:project_setting] }
        ]

        h[:squash_read_only] = {
          target_project: [{ protected_branches: :squash_option }, :project_setting]
        }
      end
    end

    def security_policy_violation_check_preloads
      [
        :scan_result_policy_reads_through_violations,
        :running_scan_result_policy_violations,
        :scan_result_policy_reads_through_approval_rules
      ]
    end

    def commits_status_mergeability_check_preloads
      [:latest_merge_request_diff]
    end

    def blocked_by_other_mrs_mergeability_check_preloads
      [:blocking_merge_requests]
    end

    def approved_mergeability_check_preloads
      nested_preloads = {
        applicable_post_merge_approval_rules: [
          :approved_approvers,
          *approval_merge_request_rules_preloads
        ],
        approval_rules: approval_merge_request_rules_preloads,
        target_project: [
          regular_or_any_approver_approval_rules: approval_project_rules_preloads
        ]
      }

      [
        :approvals, :approved_by_users, :scan_result_policy_violations, :security_policies_through_violations,
        nested_preloads
      ]
    end

    def approval_rules_preloads
      [
        :group_users,
        :users
      ]
    end

    def approval_merge_request_rules_preloads
      [
        *approval_rules_preloads,
        { approval_project_rule: approval_project_rules_preloads },
        :approval_policy_rule,
        { approval_policy_rule: [:security_policy_management_project] }
      ]
    end

    def approval_project_rules_preloads
      [
        :project,
        :protected_branches,
        *approval_rules_preloads
      ]
    end
  end
end
