# frozen_string_literal: true

module EE
  module Projects
    module AllBranchesRule
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      def approval_project_rules
        project.approval_rules.for_all_branches
      end

      def external_status_checks
        project.external_status_checks.for_all_branches
      end

      def merge_request_approval_settings
        return unless ::Feature.enabled?(:branch_rules_merge_request_approval_settings, project)

        ::Projects::AllBranchesRules::MergeRequestApprovalSetting.new(project)
      end
      strong_memoize_attr :merge_request_approval_settings
    end
  end
end
