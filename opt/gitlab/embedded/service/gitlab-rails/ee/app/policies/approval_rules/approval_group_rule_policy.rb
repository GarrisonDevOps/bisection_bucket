# frozen_string_literal: true

module ApprovalRules
  class ApprovalGroupRulePolicy < BasePolicy
    delegate { @subject.group }
  end
end
