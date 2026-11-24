# frozen_string_literal: true

module EE
  module Projects
    module ProtectDefaultBranchService
      extend ::Gitlab::Utils::Override

      override :protect_branch?
      def protect_branch?
        return true if security_policy_management_project?

        super
      end

      override :push_access_level
      def push_access_level
        return ::Gitlab::Access::NO_ACCESS if security_policy_management_project?

        super
      end

      override :code_owner_approval_required?
      def code_owner_approval_required?
        return false unless ::License.feature_available?(:code_owner_approval_required)

        default_branch_protection.code_owner_approval_required?
      end

      override :merge_access_level
      def merge_access_level
        return ::Gitlab::Access::MAINTAINER if security_policy_management_project?

        super
      end

      private

      def security_policy_management_project?
        ::Security::OrchestrationPolicyConfiguration.policy_management_project?(project.id)
      end
    end
  end
end
