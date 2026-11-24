# frozen_string_literal: true

module Cd
  class RolloutTransitionPolicy < ::BasePolicy
    delegate { @subject.rollout }
  end
end
