# frozen_string_literal: true

module ComplianceManagement
  module MergeRequestApprovalSettings
    class Resolver
      def initialize(group, project: nil)
        @group = group
        @project = project
      end

      def execute
        {
          allow_author_approval: allow_author_approval,
          allow_committer_approval: allow_committer_approval,
          allow_overrides_to_approver_list_per_merge_request: allow_overrides_to_approver_list_per_merge_request,
          retain_approvals_on_push: retain_approvals_on_push,
          selective_code_owner_removals: selective_code_owner_removals,
          require_password_to_approve: require_password_to_approve,
          require_reauthentication_to_approve: require_reauthentication_to_approve
        }
      end

      def allow_author_approval
        instance_value = !instance_settings.prevent_merge_requests_author_approval
        group_value = group_settings&.allow_author_approval
        project_value = @project && @project.read_attribute(:merge_requests_author_approval)

        setting(instance_value, group_value, project_value)
      end

      def allow_committer_approval
        instance_value = !instance_settings.prevent_merge_requests_committers_approval
        group_value = group_settings&.allow_committer_approval
        project_value = @project && !@project.read_attribute(:merge_requests_disable_committers_approval)

        setting(instance_value, group_value, project_value)
      end

      def allow_overrides_to_approver_list_per_merge_request
        instance_value = !instance_settings.disable_overriding_approvers_per_merge_request
        group_value = group_settings&.allow_overrides_to_approver_list_per_merge_request
        project_value = @project && !@project.read_attribute(:disable_overriding_approvers_per_merge_request)

        setting(instance_value, group_value, project_value,
          enforced_by_policy: @project&.policy_prevents_editing_approval_rules? || false)
      end

      def retain_approvals_on_push
        group_value = group_settings&.retain_approvals_on_push
        project_value = @project && !@project.read_attribute(:reset_approvals_on_push)

        setting(nil, group_value, project_value)
      end

      def selective_code_owner_removals
        # The 'Remove all approvals' setting takes precedence over selective CodeOwners removals
        retain_group_value = group_settings&.retain_approvals_on_push
        project_value = (@project && @project.project_setting.read_attribute(:selective_code_owner_removals)) || false

        setting(nil, retain_group_value, project_value)
      end

      def require_reauthentication_to_approve
        group_value = group_settings&.require_reauthentication_to_approve
        project_value = @project && @project.project_setting.read_attribute(:require_reauthentication_to_approve)

        ComplianceManagement::MergeRequestApprovalSettings::Setting.new(
          value: require_password_value(group_value, project_value),
          locked: require_password_locked?(group_value, false),
          inherited_from: (:group if require_password_locked?(group_value, false))
        )
      end

      def require_password_to_approve
        group_value = group_settings&.require_password_to_approve
        project_value = @project && @project.read_attribute(:require_password_to_approve)

        ComplianceManagement::MergeRequestApprovalSettings::Setting.new(
          value: require_password_value(group_value, project_value),
          locked: require_password_locked?(group_value, false),
          inherited_from: (:group if require_password_locked?(group_value, false))
        )
      end

      private

      def instance_settings
        ::Gitlab::CurrentSettings
      end

      def group_settings
        @group&.group_merge_request_approval_setting
      end

      # TODO: rename to require_reauthentication_value after: https://gitlab.com/gitlab-org/gitlab/-/issues/431346
      def require_password_value(group_value, project_value)
        [group_value, project_value].any?
      end

      def require_password_locked?(group_value, default)
        return false if @project.nil?
        return false if @group.nil?

        group_value || default
      end

      def setting(instance_value, group_value, project_value, enforced_by_policy: false)
        ComplianceManagement::MergeRequestApprovalSettings::SettingsBuilder.new(
          instance_value: instance_value,
          group_value: group_value,
          project_value: project_value,
          enforced_by_policy: enforced_by_policy
        ).to_settings
      end
    end
  end
end
