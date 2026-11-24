# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class SecurityPolicyRequirement < ApplicationRecord
      self.table_name = 'security_policy_requirements'

      belongs_to :compliance_framework_security_policy,
        class_name: 'ComplianceManagement::ComplianceFramework::SecurityPolicy',
        inverse_of: :security_policy_requirements, optional: false

      belongs_to :compliance_requirement,
        class_name: 'ComplianceManagement::ComplianceFramework::ComplianceRequirement',
        inverse_of: :security_policy_requirements, optional: false

      validates_presence_of :compliance_framework_security_policy, :compliance_requirement, :namespace_id
    end
  end
end
