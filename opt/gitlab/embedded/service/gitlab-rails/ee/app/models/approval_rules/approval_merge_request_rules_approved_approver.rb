# frozen_string_literal: true

# Model for join table between ApprovalMergeRequestRule and User
module ApprovalRules
  class ApprovalMergeRequestRulesApprovedApprover < ApplicationRecord
    include ApprovalRuleUserLike

    belongs_to :user
    belongs_to :approval_merge_request_rule, class_name: 'ApprovalMergeRequestRule'
    belongs_to :project

    validates :user, :approval_merge_request_rule, presence: true
  end
end
