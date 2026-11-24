# frozen_string_literal: true

module Cd
  class ApplicationFlowDefinitionPolicy < ::BasePolicy
    delegate { @subject.application }
  end
end
