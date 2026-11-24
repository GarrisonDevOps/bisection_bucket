# frozen_string_literal: true

module Govern
  module PolicyEngine
    # One drifted setting, read out of a violation detail. The detail names
    # the setting by its dotted context path, which GOVERN-017 fixes as the
    # contract between a policy and an enforcement point, and the writer needs
    # the bare name the project row carries.
    class SettingDrift
      PATH_SEPARATOR = '.'

      attr_reader :setting, :expected, :actual

      # A detail that names no project setting gives nothing to write, so this
      # is nil: a custom Rego rule reports no path at all, and a path under
      # another subject is not this writer's to converge.
      def self.from_detail(detail)
        return unless detail.is_a?(Hash)

        path = detail[ViolationDetails::PATH_KEY]
        return unless path.is_a?(String)

        *prefix, setting = path.split(PATH_SEPARATOR)
        return unless prefix == ProjectSettingsContext::SETTINGS_PATH && setting.present?

        new(setting, detail)
      end

      def initialize(setting, detail)
        @setting = setting
        @expected = detail[ViolationDetails::EXPECTED_KEY]
        @actual = detail[ViolationDetails::ACTUAL_KEY]
        @actual_recorded = detail.key?(ViolationDetails::ACTUAL_KEY)
      end

      # True when the setting holds a third value now. Someone changed it after
      # the evaluation, and a write would undo that change unseen.
      def changed_since_evaluation?(current)
        @actual_recorded && current != actual
      end
    end
  end
end
