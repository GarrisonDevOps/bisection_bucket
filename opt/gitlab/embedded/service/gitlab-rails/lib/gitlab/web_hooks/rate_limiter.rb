# frozen_string_literal: true

module Gitlab
  module WebHooks
    class RateLimiter
      include Gitlab::Utils::StrongMemoize

      LIMIT_NAME = :web_hook_calls
      ORGANIZATION_RATE_LIMIT_KEY = :organization_web_hook_calls
      NO_LIMIT = 0
      # ServiceHooks (integration hooks) are not rate-limited. SystemHooks in the
      # default organization (instance admin hooks) are not rate-limited either.
      EXCLUDED_HOOK_TYPES = %w[ServiceHook].freeze

      def initialize(hook)
        @hook = hook
        @parent = hook.parent
      end

      # Increments the rate-limit counter.
      # Returns true if the hook should be rate-limited.
      def rate_limit!
        return false if no_limit?

        ::Gitlab::ApplicationRateLimiter.throttled?(
          rate_limit_key,
          scope: scope,
          threshold: limit
        )
      end

      # Returns true if the hook is currently over its rate-limit.
      # It does not increment the rate-limit counter.
      def rate_limited?
        return false if no_limit?

        Gitlab::ApplicationRateLimiter.peek(
          rate_limit_key,
          scope: scope,
          threshold: limit
        )
      end

      def limit
        strong_memoize(:limit) do
          next NO_LIMIT if excluded_hook?

          limits.limit_for(limit_name) || NO_LIMIT
        end
      end

      private

      attr_reader :hook, :parent

      def no_limit?
        limit == NO_LIMIT || Feature.enabled?(:no_webhook_rate_limit, feature_flag_actor)
      end

      def excluded_hook?
        hook.class.name.in?(EXCLUDED_HOOK_TYPES) || (hook.is_a?(SystemHook) && hook.default_organization?)
      end

      # System hooks managed by organization admins have no namespace,
      # so they are limited per organization using the default plan.
      def organization_hook?
        strong_memoize(:organization_hook) do
          hook.is_a?(SystemHook) && !hook.default_organization?
        end
      end

      def limits
        return organization_plan.actual_limits if organization_hook?

        root_namespace.actual_limits
      end

      def organization_plan
        ::GitlabSubscriptions::SystemDefined::Plan.default
      end

      def scope
        organization_hook? ? { organization: hook.organization } : { namespace: root_namespace }
      end

      def rate_limit_key
        organization_hook? ? ORGANIZATION_RATE_LIMIT_KEY : limit_name
      end

      def feature_flag_actor
        organization_hook? ? hook.organization : root_namespace
      end

      def root_namespace
        @root_namespace ||= parent.root_ancestor
      end

      def limit_name
        LIMIT_NAME
      end
    end
  end
end

Gitlab::WebHooks::RateLimiter.prepend_mod
