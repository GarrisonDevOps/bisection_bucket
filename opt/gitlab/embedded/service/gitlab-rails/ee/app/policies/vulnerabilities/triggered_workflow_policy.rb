# frozen_string_literal: true

module Vulnerabilities
  class TriggeredWorkflowPolicy < BasePolicy
    delegate { @subject.vulnerability_occurrence }
  end
end
