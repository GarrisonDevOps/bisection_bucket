# frozen_string_literal: true

module EE
  module Gitlab
    module Checks
      module BranchCheck
        extend ::Gitlab::Utils::Override

        override :protected_branch_push_checks
        def protected_branch_push_checks
          return if change_access.security_policy_bypass.protected_branch_bypass_granted?

          super
        end

        override :allow_force_push?
        def allow_force_push?
          return true if change_access.security_policy_bypass.protected_branch_bypass_granted?

          super
        end
      end
    end
  end
end
