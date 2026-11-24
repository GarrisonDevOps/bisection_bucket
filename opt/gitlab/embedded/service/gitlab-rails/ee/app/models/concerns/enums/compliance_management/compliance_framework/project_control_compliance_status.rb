# frozen_string_literal: true

module Enums # rubocop:disable Gitlab/BoundedContexts -- Existing module
  module ComplianceManagement
    module ComplianceFramework
      module ProjectControlComplianceStatus
        def self.status
          {
            pass: 0,
            fail: 1,
            pending: 2,
            not_applicable: 3
          }.freeze
        end
      end
    end
  end
end
