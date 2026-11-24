# frozen_string_literal: true

module EE
  module Projects
    module BranchRule
      extend Forwardable

      def_delegators(:protected_branch, :external_status_checks, :group_level?)

      def approval_project_rules
        protected_branch.approval_project_rules_with_unique_policies
      end

      def default_branch?
        return protected_branch.name == project.default_branch if protected_branch.group_level?

        super
      end

      def squash_option
        return unless project.licensed_feature_available?(:branch_rule_squash_options)

        protected_branch.squash_option
      end
    end
  end
end
