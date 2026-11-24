# frozen_string_literal: true

module Cd
  class ServicePolicy < ::BasePolicy
    delegate { @subject.application }
  end
end
