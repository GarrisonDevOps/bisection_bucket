# frozen_string_literal: true

module ComplianceManagement
  module MergeRequestApprovalSettings
    class SettingsBuilder
      def initialize(instance_value:, group_value:, project_value:, enforced_by_policy: false)
        @instance_value = instance_value
        @group_value = group_value
        @project_value = project_value
        @enforced_by_policy = enforced_by_policy
      end

      def locked?
        return true if enforced_by_policy

        # At the group-level view there is no project setting (project_value is nil),
        # so the value can only be locked by the instance setting forcing it to false.
        return instance_value == false if project_value.nil?

        inherited = [group_value, instance_value].compact
        inherited.any?(false)
      end

      def value
        return false if enforced_by_policy

        [instance_value, group_value, project_value].compact.all?
      end

      def inherited_from
        return if enforced_by_policy
        return :instance if instance_value == false
        return :group if group_value == false && !project_value.nil?

        nil
      end

      def to_settings
        Setting.new(
          value: value,
          locked: locked?,
          inherited_from: inherited_from,
          enforced_by_policy: enforced_by_policy
        )
      end

      private

      attr_reader :instance_value, :group_value, :project_value, :enforced_by_policy
    end
  end
end
