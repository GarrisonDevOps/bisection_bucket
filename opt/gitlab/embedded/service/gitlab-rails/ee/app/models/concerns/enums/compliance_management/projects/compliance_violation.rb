# frozen_string_literal: true

module Enums # rubocop:disable Gitlab/BoundedContexts -- Existing module
  module ComplianceManagement
    module Projects
      module ComplianceViolation
        def self.status
          {
            detected: 0,
            in_review: 1,
            resolved: 2,
            dismissed: 3
          }.freeze
        end
      end
    end
  end
end
