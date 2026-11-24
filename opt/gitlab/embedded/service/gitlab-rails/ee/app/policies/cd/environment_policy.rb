# frozen_string_literal: true

module Cd
  class EnvironmentPolicy < ::BasePolicy
    delegate { @subject.organization }
  end
end
