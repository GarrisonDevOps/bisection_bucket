# frozen_string_literal: true

module Projects
  class AllProtectedBranchesRule < BranchRule
    include Projects::CustomBranchRule

    def name
      _('All protected branches')
    end

    def matching_branches_count
      project.repository.branch_names.count do |branch_name|
        ProtectedBranch.protected?(project, branch_name)
      end
    end

    def approval_project_rules
      project.approval_rules.for_all_protected_branches
    end

    def external_status_checks
      []
    end
  end
end
