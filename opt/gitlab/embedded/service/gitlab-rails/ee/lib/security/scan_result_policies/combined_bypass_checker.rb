# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class CombinedBypassChecker
      include Gitlab::Utils::StrongMemoize

      CombinedBypassResult = Struct.new(:protected_branch, :policy, :bypass_reason_required, keyword_init: true)

      def initialize(project:, user_access:, branch_name:, push_options:, audit: true)
        @project = project
        @user_access = user_access
        @branch_name = branch_name
        @push_options = push_options
        @audit = audit
      end

      def protected_branch_bypass_granted?
        bypass_result.protected_branch
      end

      def policy_bypass_granted?
        bypass_result.policy
      end

      def bypass_reason_required?
        bypass_result.bypass_reason_required
      end

      private

      attr_reader :project, :user_access, :branch_name, :push_options, :audit

      def bypass_result
        result = CombinedBypassResult.new(protected_branch: false, policy: false, bypass_reason_required: false)

        if check_protected_branch_bypass
          result.protected_branch = true
          result.policy = true
          return result
        end

        check_policy_bypass(result)

        result
      end
      strong_memoize_attr :bypass_result

      def check_protected_branch_bypass
        PushBypassChecker.new(
          project: project,
          user_access: user_access,
          branch_name: branch_name,
          bypass_context: BypassContexts::ProtectedBranchContext.new(push_options: push_options),
          audit: audit
        ).check_bypass!
      end

      def check_policy_bypass(result)
        result.policy = PushBypassChecker.new(
          project: project,
          user_access: user_access,
          branch_name: branch_name,
          bypass_context: BypassContexts::PushPolicyContext.new(push_options: push_options),
          audit: audit
        ).check_bypass!
      rescue PolicyBypassChecker::BypassReasonRequiredError
        result.bypass_reason_required = true
      end
    end
  end
end
