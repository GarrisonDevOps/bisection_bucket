# frozen_string_literal: true

module Cd
  class RolloutStepPolicy < ::BasePolicy
    delegate { @subject.rollout }
  end
end
