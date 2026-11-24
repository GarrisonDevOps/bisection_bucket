# frozen_string_literal: true

module Gitlab
  module PolicyStore
    module Rules
      SETTING_VALIDATION = 'setting_validation'

      ALL = [
        { id: 'custom', name: 'Custom' }.freeze,
        { id: 'calendar', name: 'Calendar' }.freeze,
        { id: 'environment', name: 'Environment' }.freeze,
        { id: SETTING_VALIDATION, name: 'Project setting validation' }.freeze
      ].freeze
    end
  end
end
