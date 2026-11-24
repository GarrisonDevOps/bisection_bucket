# frozen_string_literal: true

# Model for join table between ApprovalMergeRequestRule and User
class ApprovalMergeRequestRulesUser < ApplicationRecord # rubocop:disable Gitlab/NamespacedClass -- Conventional name for a join class
  include ApprovalRuleUserLike

  belongs_to :project, optional: false
  belongs_to :user
  belongs_to :approval_merge_request_rule, class_name: 'ApprovalMergeRequestRule'

  scope :for_approval_merge_request_rules, ->(approval_merge_request_rules) do
    where(approval_merge_request_rule: approval_merge_request_rules)
  end
end
