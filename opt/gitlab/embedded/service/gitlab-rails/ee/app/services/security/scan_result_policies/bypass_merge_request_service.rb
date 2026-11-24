# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class BypassMergeRequestService
      include ::Gitlab::Utils::StrongMemoize

      def initialize(merge_request:, current_user:, params:)
        @merge_request = merge_request
        @current_user = current_user
        @params = params
      end

      def execute
        return error('Security policies not found') if security_policies.blank?
        return error('Reason is required') if reason.blank?

        validation_result = validate_all_policies
        return validation_result if validation_result.error?

        bypass_all_policies!
        trigger_merge_request_update_subscriptions
        success
      end

      private

      delegate :project, to: :merge_request
      attr_reader :merge_request, :current_user, :params

      def security_policies
        project.security_policies.id_in(params[:security_policy_ids])
      end
      strong_memoize_attr :security_policies

      def reason
        params[:reason]
      end
      strong_memoize_attr :reason

      def validate_all_policies
        security_policies.each do |security_policy|
          if security_policy.merge_request_bypassed?(merge_request)
            return error('You have already bypassed this security policy.')
          end

          unless security_policy.merge_request_bypass_allowed?(merge_request, current_user)
            return error('You are not allowed to bypass this security policy.')
          end
        end

        ServiceResponse.success
      end

      def bypass_all_policies!
        security_policies.each do |security_policy|
          bypass_security_policy!(security_policy)
        end
      end

      def bypass_security_policy!(security_policy)
        security_policy.create_merge_request_bypass_event!(
          project: merge_request.project,
          user: current_user,
          reason: reason,
          merge_request: merge_request
        )

        auditor = Security::ScanResultPolicies::PolicyBypassAuditor.new(
          security_policy: security_policy,
          project: project,
          user: current_user,
          branch_name: merge_request.target_branch,
          bypass_context: bypass_context
        )

        if current_user.human?
          auditor.log_merge_request_bypass
          return
        end

        bot_checker = Security::ScanResultPolicies::BotBypassChecker.new(
          bypass_settings: security_policy.bypass_settings, user: current_user
        )

        if bot_checker.service_account_id.present?
          auditor.log_service_account_bypass(bot_checker.service_account_id)
        elsif bot_checker.access_token_ids.present?
          auditor.log_access_token_bypass(bot_checker.access_token_ids)
        else
          auditor.log_merge_request_bypass
        end
      end

      def bypass_context
        BypassContexts::MergeRequestContext.new(merge_request: merge_request, reason: reason)
      end
      strong_memoize_attr :bypass_context

      def trigger_merge_request_update_subscriptions
        GraphqlTriggers.merge_request_approval_state_updated(merge_request)
        GraphqlTriggers.merge_request_merge_status_updated(merge_request)
      end

      def error(message)
        ServiceResponse.error(message: message)
      end

      def success
        ServiceResponse.success(payload: { merge_request: merge_request })
      end
    end
  end
end
