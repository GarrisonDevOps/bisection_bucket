# frozen_string_literal: true

module ApprovalRules
  class FinalizeService
    include Gitlab::Utils::StrongMemoize

    attr_reader :merge_request

    def initialize(merge_request)
      @merge_request = merge_request
    end

    def execute
      return unless merge_request.merged?

      merge_request.finalize_rules do
        # Reads CODEOWNERS from Gitaly, so resolve it before the transaction opens
        wrapped_code_owner_rules.each(&:approvals_required_pre_merge)

        ApplicationRecord.transaction do
          handling_of_rules

          merge_request.approval_rules.each(&:sync_approved_approvers)
        end
      end
    end

    private

    def handling_of_rules
      if merge_request.approval_state.approval_rules_overwritten?
        merge_group_members_into_users
      else
        copy_project_rules
      end

      update_code_owner_rules
    end

    def update_code_owner_rules
      wrapped_code_owner_rules.each(&:finalize!)
    end

    def wrapped_code_owner_rules
      merge_request.approval_rules.code_owner.map do |rule|
        ApprovalWrappedRule.wrap(merge_request, rule)
      end
    end
    strong_memoize_attr :wrapped_code_owner_rules

    def merge_group_members_into_users
      merge_request.approval_rules.each do |rule|
        insert_group_users(rule)

        applicable_post_merge = rule.applicable_to_branch?(merge_request.target_branch)

        rule.update!(applicable_post_merge: applicable_post_merge)
      end
    end

    # Assigning through the habtm association validates every User record, so insert the join rows directly
    def insert_group_users(rule)
      user_ids = rule.group_user_ids - rule.user_ids
      return if user_ids.empty?

      rows = user_ids.map do |user_id|
        { approval_merge_request_rule_id: rule.id, user_id: user_id, project_id: merge_request.target_project_id }
      end

      ApprovalMergeRequestRulesUser.insert_all(rows, unique_by: [:approval_merge_request_rule_id, :user_id])
      rule.users.reset
    end

    def copy_project_rules
      attributes_to_slice = %w[approvals_required name report_type rule_type]

      # All User Defined MR rules are not applicable as we used project rules during merge
      # All other rules need to take into consideration if they are applicable or not
      applicable_ids = merge_request.approval_rules.not_regular_or_any_approver
        .applicable_to_branch(merge_request.target_branch)
        .map(&:id)

      merge_request.approval_rules.set_applicable_when_copying_rules(applicable_ids)

      merge_request.target_project.regular_or_any_approver_approval_rules.each do |project_rule|
        users = project_rule.approvers
        groups = project_rule.groups.public_or_visible_to_user(merge_request.author)
        applicable_post_merge = project_rule.applies_to_branch?(merge_request.target_branch)

        attributes = project_rule.attributes.slice(*attributes_to_slice)
        attributes = attributes.merge(applicable_post_merge: applicable_post_merge)

        new_rule = merge_request.approval_rules.build(attributes)

        if new_rule.valid?
          new_rule.save!
          copy_approvers(new_rule, users, groups)
        else
          merge_request.approval_rules.delete(new_rule)

          Gitlab::AppLogger.debug(
            "Failed to persist approval rule: #{new_rule.errors.full_messages}."
          )
        end
      end
    end

    # Building the rule with `users:` makes autosave validate every User record
    # inside the transaction, so insert the join rows directly instead.
    def copy_approvers(rule, users, groups)
      rows = users.map(&:id).uniq.map do |user_id|
        { approval_merge_request_rule_id: rule.id, user_id: user_id, project_id: merge_request.target_project_id }
      end

      if rows.any?
        ApprovalMergeRequestRulesUser.insert_all(rows, unique_by: [:approval_merge_request_rule_id, :user_id])
        rule.users.reset
      end

      rule.groups = groups
    end
  end
end
