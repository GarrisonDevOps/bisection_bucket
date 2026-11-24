# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ComplianceRequirement < ApplicationRecord
      self.table_name = 'compliance_requirements'

      MAX_COMPLIANCE_REQUIREMENTS_PER_FRAMEWORK_COUNT = 50

      belongs_to :framework, class_name: 'ComplianceManagement::Framework', optional: false
      belongs_to :namespace, optional: false

      validates_presence_of :framework, :namespace_id, :name, :description
      validates :name, uniqueness: { scope: :framework_id }
      validate :requirements_count_per_framework
      validates :name, length: { maximum: 255 }
      validates :description, length: { maximum: 500 }
      validate :framework_belongs_to_same_namespace

      has_many :security_policy_requirements,
        class_name: 'ComplianceManagement::ComplianceFramework::SecurityPolicyRequirement'

      has_many :compliance_framework_security_policies,
        through: :security_policy_requirements,
        inverse_of: :compliance_requirements

      has_many :compliance_requirements_controls,
        class_name: 'ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl',
        inverse_of: :compliance_requirement
      has_many :project_control_compliance_statuses,
        class_name: 'ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus'
      has_many :project_requirement_compliance_statuses,
        class_name: 'ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus'

      scope :for_framework, ->(framework_id) {
        where(framework_id: framework_id)
      }

      scope :without_controls, -> {
        left_joins(:compliance_requirements_controls)
          .where(compliance_requirements_controls: { id: nil })
      }

      private

      def requirements_count_per_framework
        if framework.nil? || framework.compliance_requirements.count < MAX_COMPLIANCE_REQUIREMENTS_PER_FRAMEWORK_COUNT
          return
        end

        errors.add(:framework, format(_("cannot have more than %{count} requirements"),
          count: MAX_COMPLIANCE_REQUIREMENTS_PER_FRAMEWORK_COUNT))
      end

      def framework_belongs_to_same_namespace
        return if namespace_id.nil? || framework.nil? || namespace_id == framework.namespace_id

        errors.add(:namespace, "must be the same as the framework's namespace.")
      end
    end
  end
end
