# frozen_string_literal: true

# Service to determine if the given namespace has a future renewal
# created in the CustomersDot application
#
# If there is a problem querying CustomersDot, it assumes there is no
# future renewal
#
# returns true, false
module GitlabSubscriptions
  class CheckFutureRenewalService
    def initialize(namespace:)
      @namespace = namespace.root_ancestor
    end

    def execute
      return false unless namespace.gitlab_subscription.present?

      future_renewal
    end

    private

    attr_reader :namespace

    def client
      Gitlab::SubscriptionPortal::Client
    end

    def next_term_start_date_request
      response = client.subscription_next_term_start_date(namespace.id)

      if response[:success]
        response[:next_term_start_date].present?
      else
        nil
      end
    end

    def cache
      Rails.cache
    end

    def cache_key
      "subscription:future_renewal:namespace:#{namespace.gitlab_subscription.cache_key}"
    end

    def future_renewal
      cache.fetch(cache_key, skip_nil: true, expires_in: 1.day) { next_term_start_date_request } || false
    end
  end
end
