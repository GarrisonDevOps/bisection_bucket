# frozen_string_literal: true

module Security
  class PolicyDismissalPolicy < BasePolicy
    delegate { @subject.project }
  end
end
