# frozen_string_literal: true

module Cd
  class DeploymentTransitionPolicy < ::BasePolicy
    delegate { @subject.deployment }
  end
end
