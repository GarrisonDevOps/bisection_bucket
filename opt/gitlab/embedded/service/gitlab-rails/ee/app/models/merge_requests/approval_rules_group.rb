# frozen_string_literal: true

module MergeRequests
  class ApprovalRulesGroup < ApplicationRecord
    self.table_name = 'merge_requests_approval_rules_groups'

    belongs_to :approval_rule, class_name: 'MergeRequests::ApprovalRule'
    belongs_to :group

    validates :group_id, uniqueness: { scope: :approval_rule_id }
  end
end
