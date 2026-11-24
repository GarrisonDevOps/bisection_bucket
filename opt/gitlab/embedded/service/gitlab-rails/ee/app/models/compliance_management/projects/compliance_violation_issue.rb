# frozen_string_literal: true

module ComplianceManagement
  module Projects
    class ComplianceViolationIssue < ApplicationRecord
      self.table_name = 'project_compliance_violations_issues'

      belongs_to :project_compliance_violation, class_name: 'ComplianceManagement::Projects::ComplianceViolation',
        inverse_of: :compliance_violation_issues
      belongs_to :issue
      belongs_to :project

      validates_presence_of :project_compliance_violation, :issue, :project

      # Validate associations for data consistency
      validate :violation_belongs_to_project

      private

      def violation_belongs_to_project
        if project_compliance_violation && project_id && project_compliance_violation.project_id != project_id
          errors.add(:project_compliance_violation, _('must belong to the specified project'))
        end
      end
    end
  end
end
