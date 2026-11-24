# frozen_string_literal: true

module API
  module Entities
    module ProtectedEnvironments
      class ApprovalRuleForSummary < ApprovalRule
        expose :deployment_approvals, using: ::API::Entities::Deployments::Approval, documentation: { is_array: true }
      end
    end
  end
end
