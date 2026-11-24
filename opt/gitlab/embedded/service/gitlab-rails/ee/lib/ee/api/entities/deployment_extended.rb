# frozen_string_literal: true

module EE
  module API
    module Entities
      module DeploymentExtended
        extend ActiveSupport::Concern

        prepended do
          expose :pending_approval_count, documentation: { type: 'Integer', example: 0 }
          expose :approvals, using: ::API::Entities::Deployments::Approval, documentation: { is_array: true }
          expose :approval_summary, using: ::API::Entities::Deployments::ApprovalSummary
        end
      end
    end
  end
end
