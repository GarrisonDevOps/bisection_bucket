# frozen_string_literal: true

module ComplianceManagement
  module MergeRequestApprovalSettings
    class Setting
      attr_reader :value, :locked, :inherited_from, :enforced_by_policy

      def initialize(value:, locked:, inherited_from:, enforced_by_policy: false)
        @value = value
        @locked = locked
        @inherited_from = inherited_from
        @enforced_by_policy = enforced_by_policy
      end
    end
  end
end
