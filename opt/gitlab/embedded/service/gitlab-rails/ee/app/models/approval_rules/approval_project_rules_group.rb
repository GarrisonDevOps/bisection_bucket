# frozen_string_literal: true

# Model for join table between ApprovalProjectRule and Group
module ApprovalRules
  class ApprovalProjectRulesGroup < ApplicationRecord
    belongs_to :group
    belongs_to :approval_project_rule, class_name: 'ApprovalProjectRule'

    validates :group, :approval_project_rule, presence: true
  end
end
