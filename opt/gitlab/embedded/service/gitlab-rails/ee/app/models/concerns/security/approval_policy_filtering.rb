# frozen_string_literal: true

module Security
  module ApprovalPolicyFiltering
    extend ActiveSupport::Concern

    def prevents_author_approval?
      target_project_prevents_author_approval? || approval_policy_prevents_author_approval?
    end

    def prevents_committer_approval?
      target_project_prevents_committer_approval? || approval_policy_prevents_committer_approval?
    end

    private

    def target_project_prevents_author_approval?
      !project.merge_requests_author_approval?
    end

    def approval_policy_prevents_author_approval?
      return false unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)

      !!approval_policy_source&.prevent_approval_by_author?
    end

    def target_project_prevents_committer_approval?
      project.merge_requests_disable_committers_approval?
    end

    def approval_policy_prevents_committer_approval?
      return false unless ::Security::PolicyAvailability.available?(project, :security_orchestration_policies)

      !!approval_policy_source&.prevent_approval_by_commit_author?
    end
  end
end
