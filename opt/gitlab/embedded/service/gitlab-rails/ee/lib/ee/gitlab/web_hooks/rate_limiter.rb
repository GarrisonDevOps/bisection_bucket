# frozen_string_literal: true

module EE
  module Gitlab
    module WebHooks
      module RateLimiter
        extend ::Gitlab::Utils::Override

        LOW_RATE_LIMIT = :web_hook_calls_low
        MID_RATE_LIMIT = :web_hook_calls_mid
        HIGH_RATE_LIMIT = ::Gitlab::WebHooks::RateLimiter::LIMIT_NAME

        PREMIUM_MID_RANGE = (100..399)
        ULTIMATE_MID_RANGE = (1_000..4_999)

        LIMIT_MAP = {
          ::GitlabSubscriptions::SystemDefined::Plan::BRONZE => PREMIUM_MID_RANGE,
          ::GitlabSubscriptions::SystemDefined::Plan::SILVER => PREMIUM_MID_RANGE,
          ::GitlabSubscriptions::SystemDefined::Plan::GOLD => ULTIMATE_MID_RANGE,
          ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM => PREMIUM_MID_RANGE,
          ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM_TRIAL => PREMIUM_MID_RANGE,
          ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE => ULTIMATE_MID_RANGE,
          ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE_TRIAL => ULTIMATE_MID_RANGE,
          ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE_TRIAL_PAID_CUSTOMER => ULTIMATE_MID_RANGE,
          ::GitlabSubscriptions::SystemDefined::Plan::OPEN_SOURCE => ULTIMATE_MID_RANGE
        }.freeze

        private

        override :limit_name
        def limit_name
          strong_memoize(:ee_limit_name) do
            # Organization hooks have no namespace, so there is no plan or seat count to step on.
            next super if organization_hook? || !paid_plan?

            # Limits for paid plans are stepped based on the number of seats
            # for the customer.
            case seats.clamp(LIMIT_MAP[plan.name]) <=> seats
            when -1 then HIGH_RATE_LIMIT
            when 0 then MID_RATE_LIMIT
            when 1 then LOW_RATE_LIMIT
            end
          end
        end

        # Organization hooks share one plan's web_hook_calls limit. On GitLab.com that limit is set
        # on the free plan. Plan.free is nil elsewhere, so this falls back to the default plan.
        override :organization_plan
        def organization_plan
          ::GitlabSubscriptions::SystemDefined::Plan.free || super
        end

        def paid_plan?
          plan.paid?
        end

        def plan
          @plan ||= root_namespace.actual_plan
        end

        def seats
          @seats ||= root_namespace.gitlab_subscription.seats
        end
      end
    end
  end
end
