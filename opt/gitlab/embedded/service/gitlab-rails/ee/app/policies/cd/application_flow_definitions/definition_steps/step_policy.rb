# frozen_string_literal: true

module Cd
  module ApplicationFlowDefinitions
    module DefinitionSteps
      class StepPolicy < ::BasePolicy
        delegate { @subject.flow_definition }
      end
    end
  end
end
