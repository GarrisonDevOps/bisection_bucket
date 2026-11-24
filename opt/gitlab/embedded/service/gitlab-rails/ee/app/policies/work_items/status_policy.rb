# frozen_string_literal: true

module WorkItems
  class StatusPolicy < BasePolicy
    delegate { @subject.namespace }
  end
end
