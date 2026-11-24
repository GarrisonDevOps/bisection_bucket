# frozen_string_literal: true

# Model for join table between ApprovalProjectRule and User
# create to enable exports ApprovalProjectRule
class ApprovalProjectRulesUser < ApplicationRecord # rubocop:disable Gitlab/NamespacedClass
  include ApprovalRuleUserLike

  belongs_to :user
  belongs_to :approval_project_rule, class_name: 'ApprovalProjectRule'
  belongs_to :project

  scope :for_project, ->(project_id) do
    joins(:approval_project_rule).where(approval_project_rule: { project_id: project_id })
  end
end
