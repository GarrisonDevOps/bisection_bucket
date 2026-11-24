# frozen_string_literal: true

module EE
  module ProtectedBranches # rubocop:disable Gitlab/BoundedContexts -- TODO: Namespacing
    class BasePolicyCheck
      # Subclass of AccessDeniedError so existing `rescue AccessDeniedError`
      # handlers keep working, while allowing callers to distinguish a
      # security-policy block from a generic authorization failure and surface a
      # clear, user-facing message instead of a generic error.
      PolicyViolationError = Class.new(::Gitlab::Access::AccessDeniedError)

      def self.check!(...)
        new(...).check!
      end

      def initialize(protected_branch, params, current_user = nil)
        @protected_branch = protected_branch
        @params = params
        @current_user = current_user
      end

      def check!
        raise PolicyViolationError, violation_message if violated?
      end

      def violated?
        raise NotImplementedError
      end

      private

      def violation_message
        _('This change is blocked by a security policy.')
      end

      attr_reader :protected_branch, :params, :current_user

      def policies_enforceable?(container)
        ::Security::PolicyAvailability.available?(container, :security_orchestration_policies)
      end

      def policy_rules_apply?(policy)
        matched_git_branches(policy).any? do |git_branch|
          protected_branch.matches?(git_branch)
        end
      end

      def matched_git_branches(policy)
        # `PolicyBranchesService` returns the empty set if the project has an
        # empty repository. But we still must block modification of branch
        # protections whose name is literally matched by a policy's `branches`.
        if protected_branch.project.empty_repo?
          # rubocop:disable CodeReuse/ActiveRecord -- Plucking a bounded result set
          return protected_branch.project.protected_branches.limit(ProtectedBranchesFinder::LIMIT).pluck(:name)
          # rubocop:enable CodeReuse/ActiveRecord
        end

        policy_branches_service.scan_result_branches(
          # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- Policy link count per project is limited
          # rubocop:disable CodeReuse/ActiveRecord -- Plucking a limited relation
          policy.undeleted_approval_policy_rules.pluck(:content).map(&:deep_symbolize_keys)
          # rubocop:enable CodeReuse/ActiveRecord
          # rubocop:enable Database/AvoidUsingPluckWithoutLimit
        )
      end

      def policy_branches_service
        @policy_branches_service ||= Security::SecurityOrchestrationPolicies::PolicyBranchesService
                                       .new(project: protected_branch.project)
      end
    end
  end
end
