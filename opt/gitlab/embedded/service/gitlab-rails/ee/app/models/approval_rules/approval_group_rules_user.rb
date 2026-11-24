# frozen_string_literal: true

# Model for join table between ApprovalGroupRule and User
# create to enable exports ApprovalGroupRule
module ApprovalRules
  class ApprovalGroupRulesUser < ApplicationRecord
    include ApprovalRuleUserLike

    belongs_to :user
    belongs_to :approval_group_rule, class_name: 'ApprovalRules::ApprovalGroupRule'
    belongs_to :group

    validates :user, :approval_group_rule, presence: true
  end
end
