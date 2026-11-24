# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ProjectRequirementComplianceStatusPolicy < BasePolicy
      delegate { @subject.compliance_framework }
    end
  end
end
