# frozen_string_literal: true

module Cd
  class RolloutPolicy < ::BasePolicy
    delegate { @subject.application }
  end
end
