# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Soc2
      class AtLeastOneNonAuthorApprovalService < BaseService
        CHECK_NAME = :at_least_one_non_author_approval

        private

        def status
          total_required_approvals = project.approval_rules.pick("SUM(approvals_required)") || 0
          prevent_approval_by_committers = project.merge_requests_disable_committers_approval?
          prevent_approval_by_author = !project.merge_requests_author_approval?

          if total_required_approvals >= 1 && prevent_approval_by_author && prevent_approval_by_committers
            :success
          else
            :fail
          end
        end
      end
    end
  end
end
