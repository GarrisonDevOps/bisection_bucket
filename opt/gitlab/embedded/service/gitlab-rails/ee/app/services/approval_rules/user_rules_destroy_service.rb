# frozen_string_literal: true

module ApprovalRules
  class UserRulesDestroyService < BaseProjectService
    def execute(user_ids)
      delete_in_batches(ApprovalProjectRulesUser.for_project(project.id).for_users(user_ids))
      delete_in_batches(
        ApprovalMergeRequestRulesUser.for_users(user_ids).for_approval_merge_request_rules(merge_request_rules)
      )
    end

    private

    def merge_request_rules
      ApprovalMergeRequestRule.for_unmerged_merge_requests.for_merge_request_project(project.id)
    end

    def delete_in_batches(relation)
      relation.each_batch do |batch|
        batch.delete_all
      end
    end
  end
end
