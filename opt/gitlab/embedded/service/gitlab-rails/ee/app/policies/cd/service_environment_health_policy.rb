# frozen_string_literal: true

module Cd
  class ServiceEnvironmentHealthPolicy < ::BasePolicy
    delegate { @subject.service }
  end
end
