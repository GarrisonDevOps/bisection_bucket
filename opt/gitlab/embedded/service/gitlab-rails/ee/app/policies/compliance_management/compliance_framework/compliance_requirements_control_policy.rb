# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ComplianceRequirementsControlPolicy < BasePolicy
      delegate { @subject.compliance_requirement.framework }
    end
  end
end
