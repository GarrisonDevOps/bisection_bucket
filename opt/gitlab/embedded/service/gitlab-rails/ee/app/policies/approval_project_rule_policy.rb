# frozen_string_literal: true

class ApprovalProjectRulePolicy < BasePolicy
  delegate { @subject.project }
end
