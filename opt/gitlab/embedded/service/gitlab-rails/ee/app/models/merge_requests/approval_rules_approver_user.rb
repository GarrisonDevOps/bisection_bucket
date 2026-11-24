# frozen_string_literal: true

module MergeRequests
  class ApprovalRulesApproverUser < ApplicationRecord
    self.table_name = 'merge_requests_approval_rules_approver_users'

    belongs_to :approval_rule, class_name: 'MergeRequests::ApprovalRule'
    belongs_to :user

    before_validation :set_sharding_key

    private

    def set_sharding_key
      return self.group_id = approval_rule.group_id if approval_rule.originates_from_group?

      self.project_id = approval_rule.project_id
    end
  end
end
