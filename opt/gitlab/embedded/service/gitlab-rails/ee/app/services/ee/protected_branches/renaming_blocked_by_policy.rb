# frozen_string_literal: true

module EE
  module ProtectedBranches
    module RenamingBlockedByPolicy
      class RenameCheck < BasePolicyCheck
        def violated?
          renaming?(protected_branch) && blocked?(protected_branch)
        end

        private

        def renaming?(protected_branch)
          return false unless params[:name]

          protected_branch.name != params[:name]
        end

        def violation_message
          _('This change is blocked by a security policy that prevents branch ' \
            'modification. Modifying the protected branch is not allowed while the ' \
            'policy applies.')
        end

        def blocked?(protected_branch)
          return blocking_branch_modification?(protected_branch.project) if protected_branch.project_level?

          blocking_group_branch_modification?(protected_branch.group)
        end

        def blocking_branch_modification?(project)
          return false unless policies_enforceable?(project)

          blocking_policies = protected_branch
            .project
            .security_policies
            .type_approval_policy
            .enabled
            .block_branch_modification
            .preload_approval_policy_rules

          blocking_policies = blocking_policies.without_warn_mode

          blocking_policies.any? { |policy| policy_rules_apply?(policy) }
        end

        def blocking_group_branch_modification?(group)
          return false unless policies_enforceable?(group)

          ::Security::SecurityOrchestrationPolicies::GroupProtectedBranchesDeletionCheckService
            .new(group: group, current_user: current_user)
            .execute
        end
      end

      def execute(protected_branch, skip_authorization: false)
        RenameCheck.check!(protected_branch, params, current_user)

        super
      end
    end
  end
end
