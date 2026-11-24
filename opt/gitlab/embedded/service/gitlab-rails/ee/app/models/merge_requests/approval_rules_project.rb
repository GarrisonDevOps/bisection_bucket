# frozen_string_literal: true

module MergeRequests
  class ApprovalRulesProject < ApplicationRecord
    self.table_name = 'merge_requests_approval_rules_projects'

    belongs_to :approval_rule, class_name: 'MergeRequests::ApprovalRule'
    belongs_to :project

    validates :project_id, uniqueness: { scope: :approval_rule_id }
  end
end
