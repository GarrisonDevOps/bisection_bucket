# frozen_string_literal: true

module EE
  module Projects
    module BranchRulesFinder
      extend ActiveSupport::Concern

      ALL_PROTECTED_BRANCHES_IDENTIFIER = 'all_protected_branches'

      private

      def identifier_for_rule(rule)
        return ALL_PROTECTED_BRANCHES_IDENTIFIER if rule.is_a?(::Projects::AllProtectedBranchesRule)

        super
      end

      def custom_rule_names
        super + [ALL_PROTECTED_BRANCHES_IDENTIFIER]
      end
    end
  end
end
