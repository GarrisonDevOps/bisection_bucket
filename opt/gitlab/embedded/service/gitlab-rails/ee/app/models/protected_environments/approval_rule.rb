# frozen_string_literal: true

module ProtectedEnvironments
  class ApprovalRule < ApplicationRecord
    include Authorizable
    include ApprovalRules::Summarizable

    self.table_name = 'protected_environment_approval_rules'

    belongs_to :protected_environment, inverse_of: :approval_rules

    has_many :deployment_approvals, class_name: 'Deployments::Approval', inverse_of: :approval_rule

    validates :access_level, allow_blank: true, inclusion: { in: ALLOWED_ACCESS_LEVELS }
    validates :required_approvals,
      numericality: { only_integer: true, greater_than_or_equal_to: 1, less_than_or_equal_to: 5 }
    validates :group_inheritance_type, inclusion: { in: GROUP_INHERITANCE_TYPE.values }

    def hook_attrs
      {
        id: id,
        user_id: user_id,
        group_id: group_id,
        access_level: access_level,
        access_level_description: humanize,
        required_approvals: required_approvals,
        group_inheritance_type: group_inheritance_type
      }
    end
  end
end
