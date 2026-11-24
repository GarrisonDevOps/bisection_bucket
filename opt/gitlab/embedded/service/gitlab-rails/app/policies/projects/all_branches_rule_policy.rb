# frozen_string_literal: true

module Projects
  class AllBranchesRulePolicy < BasePolicy
    delegate(:project) { @subject.project }

    condition(:any_deletable_features_enabled, scope: :subject) do
      @subject.project.licensed_feature_available?(:multiple_approval_rules) ||
        @subject.project.licensed_feature_available?(:external_status_checks)
    end

    rule { default }.policy do
      prevent :create_branch_rule
      prevent :update_branch_rule
    end
    rule { ~can?(:_read_custom_branch_rule) }.prevent :read_branch_rule
    rule { ~any_deletable_features_enabled | ~can?(:_delete_custom_branch_rule) }.prevent :delete_branch_rule
  end
end
