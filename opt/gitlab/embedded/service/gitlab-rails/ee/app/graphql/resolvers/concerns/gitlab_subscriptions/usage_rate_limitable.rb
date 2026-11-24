# frozen_string_literal: true

module GitlabSubscriptions
  module UsageRateLimitable
    extend ActiveSupport::Concern
    include Gitlab::Graphql::Authorize::AuthorizeResource

    RATE_LIMIT_KEYS = %i[
      subscription_usage_per_minute
      subscription_usage_per_hour
      subscription_usage_per_day
    ].freeze

    private

    def check_usage_rate_limit!(namespace)
      exceeded_keys = usage_rate_limit_keys.select do |key|
        ::Gitlab::ApplicationRateLimiter.throttled?(key, scope: { user: current_user })
      end

      return if exceeded_keys.empty?

      enforce = usage_rate_limit_enforced?(namespace)

      log_usage_rate_limit(namespace, exceeded_keys, enforce)

      return unless enforce

      raise_resource_not_available_error!(::Gitlab::ApplicationRateLimiter.throttled_error_message)
    end

    def usage_rate_limit_keys
      RATE_LIMIT_KEYS
    end

    def usage_rate_limit_enforced?(namespace)
      ::Feature.enabled?(:enforce_subscription_usage_rate_limits, namespace, type: :gitlab_com_derisk)
    end

    def usage_rate_limit_log_message
      'Subscription usage rate limit exceeded'
    end

    def log_usage_rate_limit(namespace, exceeded_keys, enforce)
      ::Gitlab::AppJsonLogger.info(
        ::Labkit::Fields::CLASS_NAME => self.class.name,
        ::Labkit::Fields::GL_USER_ID => current_user.id,
        ::Labkit::Fields::GL_ROOT_NAMESPACE_ID => namespace&.id,
        ::Labkit::Fields::LOG_MESSAGE => usage_rate_limit_log_message,
        ::Labkit::Fields::ADDITIONAL_DETAILS =>
          "exceeded_rate_limits: '#{exceeded_keys.join(',')}', throttled: #{enforce}"
      )
    end
  end
end
