# frozen_string_literal: true

# Model for join table between ApprovalMergeRequestRule and Group
module ApprovalRules
  class ApprovalMergeRequestRulesGroup < ApplicationRecord
    belongs_to :group
    belongs_to :approval_merge_request_rule, class_name: 'ApprovalMergeRequestRule'

    validates :group, :approval_merge_request_rule, presence: true
  end
end
