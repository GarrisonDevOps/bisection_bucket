# frozen_string_literal: true

module Gitlab
  module RateLimit
    # The one place a rate-limit flag is read, so the GitLab.com guard and the
    # info-gates-enforce rule cannot be forgotten at a call site.
    module FlagPolicy
      # The names, for callers that need to enumerate rather than read them:
      # spec/support/rate_limiter_labkit_rack_shadow.rb stubs them all off.
      FLAGS = [
        :rate_limiter_plan_limits_free_info,
        :rate_limiter_plan_limits_free_enforce,
        :rate_limiter_plan_limits_premium_info,
        :rate_limiter_plan_limits_premium_enforce,
        :rate_limiter_plan_limits_ultimate_info,
        :rate_limiter_plan_limits_ultimate_enforce,
        :rate_limiter_unauthenticated_limits_info,
        :rate_limiter_unauthenticated_limits_enforce,
        :rate_limiter_mcp_sustained_limits_free_info,
        :rate_limiter_mcp_sustained_limits_free_enforce,
        :rate_limiter_mcp_sustained_limits_premium_info,
        :rate_limiter_mcp_sustained_limits_premium_enforce,
        :rate_limiter_mcp_sustained_limits_ultimate_info,
        :rate_limiter_mcp_sustained_limits_ultimate_enforce,
        :rate_limiter_expired_oauth_token_per_token,
        :rate_limiter_expired_oauth_token_per_token_enforce
      ].freeze

      class << self
        def gitlab_com?
          ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        end

        # One fact per flag, uncoupled, so a rule states its own gate rather than
        # reading a boolean this file already combined. The info-gates-enforce rule
        # lives in each rule's match now, which is why nothing here folds the two
        # together.
        #
        # Always the full set, so the facts a rule matches on are present whatever
        # the flags say. Reads are cheap after the first: Feature memoizes Flipper
        # into SafeRequestStore.
        def plan_flags
          ::GitlabSubscriptions::SystemDefined::Plan::TIERS.each_with_object({}) do |plan, facts|
            facts[:"plan_limits_#{plan}_info"] = plan_info_enabled?(plan)
            facts[:"plan_limits_#{plan}_enforce"] = gitlab_com? && enforce_flag_on?(plan)
          end
        end

        def mcp_plan_flags
          ::GitlabSubscriptions::SystemDefined::Plan::TIERS.each_with_object({}) do |plan, facts|
            facts[:"mcp_sustained_limits_#{plan}_info"] = gitlab_com? && mcp_sustained_info_flag_on?(plan)
            facts[:"mcp_sustained_limits_#{plan}_enforce"] = gitlab_com? && mcp_sustained_enforce_flag_on?(plan)
          end
        end

        def plan_info_enabled?(plan)
          gitlab_com? && info_flag_on?(plan)
        end

        def unauthenticated_info_enabled?
          gitlab_com? && unauthenticated_info_flag_on?
        end

        def unauthenticated_enforce_enabled?
          unauthenticated_info_enabled? && unauthenticated_enforce_flag_on?
        end

        def expired_oauth_token_per_token_enabled?
          gitlab_com? && expired_oauth_token_flag_on?
        end

        # Never while the unauthenticated rules only log, or these would enforce while the rest shadows.
        def expired_oauth_token_per_token_enforced?
          expired_oauth_token_per_token_enabled? && unauthenticated_enforce_enabled? &&
            expired_oauth_token_enforce_flag_on?
        end

        private

        def actor
          ::Feature.current_request
        end

        # Literal flag names rather than "rate_limiter_plan_limits_#{plan}_info", so
        # every read is a static key (Gitlab/FeatureFlagKeyDynamic).
        def info_flag_on?(plan)
          case plan
          when ::GitlabSubscriptions::SystemDefined::Plan::FREE
            ::Feature.enabled?(:rate_limiter_plan_limits_free_info, actor, type: :gitlab_com_derisk)
          when ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM
            ::Feature.enabled?(:rate_limiter_plan_limits_premium_info, actor, type: :gitlab_com_derisk)
          when ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE
            ::Feature.enabled?(:rate_limiter_plan_limits_ultimate_info, actor, type: :gitlab_com_derisk)
          else
            false
          end
        end

        def enforce_flag_on?(plan)
          case plan
          when ::GitlabSubscriptions::SystemDefined::Plan::FREE
            ::Feature.enabled?(:rate_limiter_plan_limits_free_enforce, actor, type: :gitlab_com_derisk)
          when ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM
            ::Feature.enabled?(:rate_limiter_plan_limits_premium_enforce, actor, type: :gitlab_com_derisk)
          when ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE
            ::Feature.enabled?(:rate_limiter_plan_limits_ultimate_enforce, actor, type: :gitlab_com_derisk)
          else
            false
          end
        end

        def mcp_sustained_info_flag_on?(plan)
          case plan
          when ::GitlabSubscriptions::SystemDefined::Plan::FREE
            ::Feature.enabled?(:rate_limiter_mcp_sustained_limits_free_info, actor, type: :gitlab_com_derisk)
          when ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM
            ::Feature.enabled?(:rate_limiter_mcp_sustained_limits_premium_info, actor, type: :gitlab_com_derisk)
          when ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE
            ::Feature.enabled?(:rate_limiter_mcp_sustained_limits_ultimate_info, actor, type: :gitlab_com_derisk)
          else
            false
          end
        end

        def mcp_sustained_enforce_flag_on?(plan)
          case plan
          when ::GitlabSubscriptions::SystemDefined::Plan::FREE
            ::Feature.enabled?(:rate_limiter_mcp_sustained_limits_free_enforce, actor, type: :gitlab_com_derisk)
          when ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM
            ::Feature.enabled?(:rate_limiter_mcp_sustained_limits_premium_enforce, actor, type: :gitlab_com_derisk)
          when ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE
            ::Feature.enabled?(:rate_limiter_mcp_sustained_limits_ultimate_enforce, actor, type: :gitlab_com_derisk)
          else
            false
          end
        end

        def unauthenticated_info_flag_on?
          ::Feature.enabled?(:rate_limiter_unauthenticated_limits_info, actor, type: :gitlab_com_derisk)
        end

        def unauthenticated_enforce_flag_on?
          ::Feature.enabled?(:rate_limiter_unauthenticated_limits_enforce, actor, type: :gitlab_com_derisk)
        end

        def expired_oauth_token_flag_on?
          ::Feature.enabled?(:rate_limiter_expired_oauth_token_per_token, actor, type: :gitlab_com_derisk)
        end

        def expired_oauth_token_enforce_flag_on?
          ::Feature.enabled?(:rate_limiter_expired_oauth_token_per_token_enforce, actor, type: :gitlab_com_derisk)
        end
      end
    end
  end
end
