# frozen_string_literal: true

module Ai
  class UsersPerIpLimit
    RATE_LIMIT_KEY = :ai_users_per_ip
    IPV6_PREFIX_LENGTH = 48
    PAID_STATUS_CACHE_TTL = 10.minutes

    def initialize(user:, request:)
      @user = user
      @request = request
    end

    def throttled?
      return false unless enabled?
      return false if exempt_user?

      ip = ip_bucket
      return false unless ip

      throttled = ::Gitlab::ApplicationRateLimiter.throttled_request?(
        request, user, RATE_LIMIT_KEY, scope: { ip: ip }, resource: user
      )

      throttled && ::Feature.enabled?(:enforce_ai_users_per_ip_limit, user)
    end

    def period
      ::Gitlab::ApplicationRateLimiter.period_for(RATE_LIMIT_KEY)
    end

    private

    attr_reader :user, :request

    def enabled?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
        ::Feature.enabled?(:ai_users_per_ip_limit, user)
    end

    def exempt_user?
      return true unless user
      return true if user.bot?
      return true if agent_request?

      paid_user?
    end

    # Headless CI agents authenticate with a composite OAuth token and run on runners or other shared hosts, so their IP
    # is not the user's. This exemption also applies to composite-identity requests to the direct_access and
    # third_party_agents endpoints.
    def agent_request?
      ::Gitlab::Auth::Identity.resolve_composite_identity_actor(user) != user
    end

    def paid_user?
      Rails.cache.fetch(['ai_users_per_ip_limit', 'paid_user', user.id], expires_in: PAID_STATUS_CACHE_TTL) do
        user.belongs_to_paid_namespace?(plans: paid_plans, exclude_trials: true, include_all_memberships: true) ||
          ::GitlabSubscriptions::AddOnPurchase.assigned_to_user(user).non_trial.exists?
      end
    end

    # OSS licenses have been abused, so they don't exempt newer users. Mirrors IdentityVerifiable.
    def paid_plans
      plans = ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS
      return plans unless user.id_check_for_oss_enabled?

      plans.without(::GitlabSubscriptions::SystemDefined::Plan::OPEN_SOURCE)
    end

    # IPv6 clients are usually given a whole prefix, so they are bucketed by network.
    def ip_bucket
      return if request&.ip.blank?

      address = IPAddr.new(request.ip).native
      address = address.mask(IPV6_PREFIX_LENGTH) if address.ipv6?
      address.to_s
    rescue IPAddr::Error
      nil
    end
  end
end
