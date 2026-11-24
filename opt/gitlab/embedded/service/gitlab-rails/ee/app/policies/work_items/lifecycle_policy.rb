# frozen_string_literal: true

module WorkItems
  class LifecyclePolicy < BasePolicy
    delegate { @subject.namespace }
  end
end
