# frozen_string_literal: true

module Deployments
  class Approval < ApplicationRecord
    self.table_name = 'deployment_approvals'

    belongs_to :deployment
    belongs_to :user
    belongs_to :ci_build, class_name: 'Ci::Build', optional: true
    belongs_to :project

    belongs_to :approval_rule,
      class_name: 'ProtectedEnvironments::ApprovalRule',
      foreign_key: :approval_rule_id,
      inverse_of: :deployment_approvals

    # A database trigger sets project_id, so an approval just created reads its project through the deployment.
    delegate :project, to: :deployment, prefix: true, allow_nil: true

    validates :user,
      presence: true,
      uniqueness: { scope: [:deployment_id, :approval_rule_id] }
    validates :deployment, presence: true
    validates :status, presence: true
    validates :comment, length: { maximum: 255 }

    enum :status, {
      approved: 0,
      rejected: 1
    }

    def hook_attrs
      {
        id: id,
        status: status,
        comment: comment,
        created_at: created_at,
        approval_rule: approval_rule&.hook_attrs
      }
    end
  end
end
