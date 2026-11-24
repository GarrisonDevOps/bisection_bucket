# frozen_string_literal: true

module MergeRequests
  class ApprovalRulesApproverGroup < ApplicationRecord
    self.table_name = 'merge_requests_approval_rules_approver_groups'

    belongs_to :approval_rule, class_name: 'MergeRequests::ApprovalRule'
    belongs_to :group
  end
end
