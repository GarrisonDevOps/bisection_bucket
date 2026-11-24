# frozen_string_literal: true

module ComplianceManagement
  module Projects
    module ViolationDetectors
      class MinimumApprovalsRequired2Detector < BaseDetector
        def detect_violations
          create_violation if violation?
        end

        private

        def violation?
          audit_event.details[:approvers].count < 2
        end
      end
    end
  end
end
