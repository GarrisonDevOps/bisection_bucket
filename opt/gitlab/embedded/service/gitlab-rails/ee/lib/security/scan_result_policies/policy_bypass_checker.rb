# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class PolicyBypassChecker
      include Gitlab::Utils::StrongMemoize

      BypassReasonRequiredError = Class.new(StandardError)

      def initialize(
        security_policy:, project:, user_access:, branch_name:,
        bypass_context:, audit: true)
        @security_policy = security_policy
        @project = project
        @user = user_access.user
        @branch_name = branch_name
        @bypass_context = bypass_context
        @audit = audit
      end

      def bypass_allowed?
        return false unless user

        bypass_with_automated_actor? || bypass_with_user?
      end

      private

      attr_reader :security_policy, :project, :user, :branch_name, :bypass_context, :audit

      def audit_logger
        PolicyBypassAuditor.new(
          security_policy: security_policy,
          project: project,
          user: user,
          branch_name: branch_name,
          bypass_context: bypass_context
        )
      end
      strong_memoize_attr :audit_logger

      def bot_checker
        BotBypassChecker.new(bypass_settings: security_policy.bypass_settings, user: user)
      end
      strong_memoize_attr :bot_checker

      def bypass_with_automated_actor?
        return false unless bot_checker.bypass_allowed?

        if audit
          if bot_checker.service_account_id
            audit_logger.log_service_account_bypass(bot_checker.service_account_id)
          elsif bot_checker.access_token_ids
            audit_logger.log_access_token_bypass(bot_checker.access_token_ids)
          end
        end

        true
      end

      def bypass_with_user?
        user_bypass_scope = UserBypassChecker.new(
          bypass_settings: security_policy.bypass_settings, project: project, current_user: user
        ).bypass_scope

        return false unless user_bypass_scope

        reason = bypass_context.bypass_reason
        raise BypassReasonRequiredError, "Bypass reason is required for user bypass" if reason.blank?

        audit_logger.log_user_bypass(user_bypass_scope, reason) if audit
        true
      end
    end
  end
end
