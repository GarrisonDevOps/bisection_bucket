# frozen_string_literal: true

module Cd
  class RolloutEnvironmentPolicy < ::BasePolicy
    delegate { @subject.rollout }
  end
end
