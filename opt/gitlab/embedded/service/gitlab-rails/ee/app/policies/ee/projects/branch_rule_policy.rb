# frozen_string_literal: true

module EE
  module Projects
    module BranchRulePolicy
      extend ActiveSupport::Concern

      prepended do
        condition(:can_unprotect) do
          @subject.protected_branch.can_unprotect?(@user)
        end

        condition(:unprotect_restrictions_enabled, scope: :subject) do
          @subject.protected_branch.supports_unprotection_restrictions?
        end

        rule { unprotect_restrictions_enabled & ~can_unprotect }.policy do
          prevent :create_branch_rule
          prevent :update_branch_rule
          prevent :delete_branch_rule
          prevent :create_squash_option
          prevent :update_squash_option
          prevent :delete_squash_option
        end
      end
    end
  end
end
