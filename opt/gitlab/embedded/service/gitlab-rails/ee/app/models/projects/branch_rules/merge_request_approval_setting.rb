# frozen_string_literal: true

module Projects
  module BranchRules
    class MergeRequestApprovalSetting < ApplicationRecord
      belongs_to :protected_branch, optional: false
      belongs_to :project, optional: false

      enum :approval_removals, { none: 0, all: 1, code_owners: 2 }, prefix: true
    end
  end
end
