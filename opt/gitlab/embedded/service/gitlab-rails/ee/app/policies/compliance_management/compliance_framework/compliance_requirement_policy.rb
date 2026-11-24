# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ComplianceRequirementPolicy < BasePolicy
      delegate { @subject.framework }
    end
  end
end
