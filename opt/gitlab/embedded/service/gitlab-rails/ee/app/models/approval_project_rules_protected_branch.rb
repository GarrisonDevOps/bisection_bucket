# frozen_string_literal: true

# Model for join table between ApprovalProjectRule and ProtectedBranch
class ApprovalProjectRulesProtectedBranch < ApplicationRecord
  belongs_to :protected_branch
  belongs_to :approval_project_rule
  belongs_to :project

  def branch_name
    protected_branch.name
  end
end
