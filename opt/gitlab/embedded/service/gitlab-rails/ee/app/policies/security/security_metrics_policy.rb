# frozen_string_literal: true

module Security
  class SecurityMetricsPolicy < BasePolicy
    delegate { @subject.object }
  end
end
