# frozen_string_literal: true

# Model for join table between ApprovalGroupRule and Group
module ApprovalRules
  class ApprovalGroupRulesGroup < ApplicationRecord
    belongs_to :group
    belongs_to :approval_group_rule, class_name: 'ApprovalRules::ApprovalGroupRule'

    validates :group, :approval_group_rule, presence: true
  end
end
