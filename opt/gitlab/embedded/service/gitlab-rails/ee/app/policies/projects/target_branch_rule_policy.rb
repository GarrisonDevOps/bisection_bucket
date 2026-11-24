# frozen_string_literal: true

module Projects
  class TargetBranchRulePolicy < BasePolicy
    delegate { @subject.project }
  end
end
