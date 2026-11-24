# frozen_string_literal: true

module Vulnerabilities
  class StateTransitionPolicy < BasePolicy
    delegate { @subject.vulnerability.project }
  end
end
