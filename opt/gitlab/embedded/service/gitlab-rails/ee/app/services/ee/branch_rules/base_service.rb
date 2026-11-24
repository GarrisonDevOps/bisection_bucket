# frozen_string_literal: true

module EE
  module BranchRules
    module BaseService
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        delegate :approval_project_rules, :external_status_checks, to: :branch_rule, allow_nil: true, private: true
      end

      private

      def all_protected_branches_rule?
        branch_rule.is_a?(::Projects::AllProtectedBranchesRule)
      end

      override :execute_on_branch_rule_type
      def execute_on_branch_rule_type
        return execute_on_all_protected_branches_rule if all_protected_branches_rule?

        super
      end

      override :handle_access_denied_error
      def handle_access_denied_error(error)
        return super unless error.is_a?(::EE::ProtectedBranches::BasePolicyCheck::PolicyViolationError)

        # Surface a clear, user-facing message (shown by the frontend) instead of
        # a generic "resource not available" error. Uses :unprocessable_entity so
        # the GraphQL mutation returns it in `errors` rather than raising.
        ServiceResponse.error(
          message: error.message,
          reason: :unprocessable_entity
        )
      end

      def execute_on_all_protected_branches_rule
        missing_method_error('execute_on_all_protected_branches_rule')
      end
    end
  end
end
