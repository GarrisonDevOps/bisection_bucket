# frozen_string_literal: true

module Cd
  class EnvironmentDriverBindingPolicy < ::BasePolicy
    delegate { @subject.environment }
  end
end
