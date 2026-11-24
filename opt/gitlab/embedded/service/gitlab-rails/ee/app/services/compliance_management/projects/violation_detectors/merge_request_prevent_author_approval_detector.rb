# frozen_string_literal: true

module ComplianceManagement
  module Projects
    module ViolationDetectors
      class MergeRequestPreventAuthorApprovalDetector < BaseDetector
        def detect_violations
          create_violation if violation?
        end

        private

        def violation?
          audit_event.details[:approving_author] == true
        end
      end
    end
  end
end
