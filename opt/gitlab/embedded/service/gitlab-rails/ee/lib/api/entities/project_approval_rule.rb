# frozen_string_literal: true

module API
  module Entities
    class ProjectApprovalRule < ::API::Entities::ApprovalRule
      expose :protected_branches,
        using: ::API::Entities::ProtectedBranch,
        if: ->(rule, _) { rule.project.multiple_approval_rules_available? }, documentation: { is_array: true }
      expose :applies_to_all_protected_branches, documentation: { type: 'Boolean' }
      expose :coverage_minimum_threshold, documentation: { type: 'Float', example: 80.0 },
        if: ->(rule, _) { rule.report_type == 'code_coverage' }
    end
  end
end
