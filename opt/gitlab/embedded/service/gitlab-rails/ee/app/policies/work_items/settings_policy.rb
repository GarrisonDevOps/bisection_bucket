# frozen_string_literal: true

module WorkItems
  class SettingsPolicy < BasePolicy
    delegate { @subject.namespace || @subject.organization }
  end
end
