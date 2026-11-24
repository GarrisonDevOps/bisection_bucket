# frozen_string_literal: true

module API
  module Entities
    class GroupApprovalRule < ::API::Entities::ApprovalRule
      expose :protected_branches,
        using: ::API::Entities::ProtectedBranch,
        if: ->(rule, _) { rule.group.multiple_approval_rules_available? }, documentation: { is_array: true }
      expose :applies_to_all_protected_branches, documentation: { type: 'Boolean' }
    end
  end
end
