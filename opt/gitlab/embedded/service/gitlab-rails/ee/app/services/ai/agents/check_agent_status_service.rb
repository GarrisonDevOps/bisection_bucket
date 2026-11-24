# frozen_string_literal: true

module Ai
  module Agents
    class CheckAgentStatusService
      include Gitlab::Utils::StrongMemoize

      class AgentStatus
        attr_reader :disabled, :disabled_reason

        alias_method :disabled?, :disabled

        class << self
          def enabled
            new(disabled: false)
          end

          def disabled(reason)
            new(disabled: true, disabled_reason: reason)
          end
        end

        def initialize(disabled:, disabled_reason: "")
          @disabled = disabled
          @disabled_reason = disabled_reason
        end

        def enabled?
          !disabled?
        end
      end

      def initialize(current_user)
        @current_user = current_user
      end

      def execute(user)
        return AgentStatus.enabled unless agent?(user)

        # Amazon Q is licensed via the duo_amazon_q add-on, not via Duo Agent
        # Platform usage credits, so its service account must not be subjected to
        # a DAP usage quota check even though it is a composite identity agent.
        # See https://gitlab.com/gitlab-com/request-for-help/-/work_items/4859
        return AgentStatus.enabled if ::Ai::Setting.amazon_q_service_account?(user)

        result = usage_quota_service_result
        result.success? ? AgentStatus.enabled : AgentStatus.disabled(reason_for(result))
      end

      private

      attr_reader :current_user

      def agent?(user)
        user.composite_ai_service_account?
      end

      def reason_for(result)
        case result.reason
        when :user_missing
          s_("CheckAgentStatusService|Unavailable - invalid user")
        when :namespace_missing
          s_("CheckAgentStatusService|Unavailable - missing default namespace")
        when :usage_quota_exceeded
          s_("CheckAgentStatusService|Unavailable - no credits")
        when :usage_billing_forbidden
          s_("CheckAgentStatusService|Unavailable - subscription is not eligible for usage-based billing")
        else
          s_("CheckAgentStatusService|Unavailable - unknown reason")
        end
      end

      def usage_quota_service_result
        ::Ai::UsageQuotaService.new(user: current_user).execute
      end
      strong_memoize_attr :usage_quota_service_result
    end
  end
end
