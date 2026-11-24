# frozen_string_literal: true

module GitlabSubscriptions
  class FetchSubscriptionPlansService
    def initialize(plan:, namespace_id: nil)
      @plan = plan
      @namespace_id = namespace_id
    end

    def execute
      cached { send_request }
    end

    private

    def send_request
      plans_url = ::Gitlab::Routing.url_helpers.subscription_portal_gitlab_plans_url

      response = Gitlab::HTTP.get(
        plans_url,
        allow_local_requests: true,
        query: { plan: @plan, namespace_id: @namespace_id },
        headers: { 'Accept' => 'application/json' }
      )

      Gitlab::Json.safe_parse(response.body).map { |plan| Hashie::Mash.new(plan) }
    rescue StandardError => e
      Gitlab::AppLogger.info "Unable to connect to GitLab Customers App #{e}"

      nil
    end

    def cached
      if plans_data = cache.read(cache_key)
        plans_data
      else
        cache.fetch(cache_key, force: true, expires_in: 1.day) { yield }
      end
    end

    def cache
      Rails.cache
    end

    def cache_key
      if @namespace_id.present?
        "subscription-plans-#{@plan}-#{@namespace_id}"
      else
        "subscription-plans-#{@plan}"
      end
    end
  end
end
