# frozen_string_literal: true

module Security
  module DependencyFirewall
    class AuditBypassesService
      def initialize(project, current_user:, results:, purl:, operation:, session_id: nil)
        @project = project
        @current_user = current_user
        @results = results
        @purl = purl
        @operation = operation
        @session_id = session_id
      end

      def execute
        results.each { |result| audit_bypass(result) }
      end

      private

      attr_reader :project, :current_user, :results, :purl, :operation, :session_id

      def audit_bypass(result)
        security_policy = result[:security_policy]

        case result[:reason]
        when :user_bypassed
          auditor(security_policy).log_user_bypass(:user, nil)
        when :token_bypassed
          token_ids = security_policy.bypass_settings.bypassing_access_token_ids(current_user)
          auditor(security_policy).log_access_token_bypass(token_ids)
        end
      # An audit failure must never break package enforcement, and one failed policy must not skip the rest.
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, project_id: project.id, security_policy_id: security_policy.id)
      end

      def auditor(security_policy)
        ::Security::ScanResultPolicies::PolicyBypassAuditor.new(
          security_policy: security_policy,
          project: project,
          user: current_user,
          branch_name: nil,
          bypass_context: bypass_context
        )
      end

      def bypass_context
        ::Security::ScanResultPolicies::BypassContexts::DependencyFirewallContext.new(
          purl: purl,
          operation: CreateAuditEventsService.operation_label(operation),
          session_id: session_id
        )
      end
    end
  end
end
