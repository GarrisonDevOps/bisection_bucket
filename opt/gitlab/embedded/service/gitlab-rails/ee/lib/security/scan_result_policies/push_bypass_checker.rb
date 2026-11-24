# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class PushBypassChecker
      include Gitlab::Utils::StrongMemoize

      def initialize(project:, user_access:, branch_name:, bypass_context:, audit: true)
        @project = project
        @user_access = user_access
        @branch_name = branch_name
        @bypass_context = bypass_context
        @audit = audit
      end

      def check_bypass!
        return false unless project.licensed_feature_available?(:security_orchestration_policies)

        policies = filtered_policies
        return false if policies.empty?

        policies.any? { |policy| bypass_allowed?(policy) }
      end

      private

      attr_reader :project, :user_access, :branch_name, :bypass_context, :audit

      def filtered_policies
        project.approval_policies.with_bypass_settings
      end

      def bypass_allowed?(policy)
        Security::ScanResultPolicies::PolicyBypassChecker.new(
          security_policy: policy,
          project: project,
          user_access: user_access,
          branch_name: branch_name,
          bypass_context: bypass_context,
          audit: audit
        ).bypass_allowed?
      rescue Security::ScanResultPolicies::PolicyBypassChecker::BypassReasonRequiredError
        raise unless bypass_context.suppress_reason_required_error?

        false
      end
    end
  end
end
