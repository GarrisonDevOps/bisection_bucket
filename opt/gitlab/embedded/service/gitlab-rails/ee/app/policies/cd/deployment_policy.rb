# frozen_string_literal: true

module Cd
  class DeploymentPolicy < ::BasePolicy
    delegate { @subject.service }
  end
end
