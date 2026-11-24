# frozen_string_literal: true

module Cd
  class RolloutGatePolicy < ::BasePolicy
    delegate { @subject.rollout }
  end
end
