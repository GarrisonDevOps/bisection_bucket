# frozen_string_literal: true

module GitlabSubscriptions
  class FetchMonthlyCommitmentService
    CACHE_TTL = 1.hour
    CACHE_MODES = %i[none read refresh].freeze
    private_constant :CACHE_TTL, :CACHE_MODES

    def initialize(namespace_id:, cache_mode: :none)
      validate_cache_mode!(cache_mode)

      @namespace_id = namespace_id
      @cache_mode = cache_mode
    end

    def execute
      total_credits = cache_mode == :none ? fetch_total_credits : cached_total_credits

      if total_credits.nil?
        return ServiceResponse.error(message: 'Failed to fetch monthly commitment', payload: { total_credits: 0 })
      end

      ServiceResponse.success(payload: { total_credits: total_credits })
    end

    private

    attr_reader :namespace_id, :cache_mode

    def validate_cache_mode!(cache_mode)
      return if CACHE_MODES.include?(cache_mode)

      raise ArgumentError, "Unknown cache mode: #{cache_mode.inspect}"
    end

    def cached_total_credits
      Rails.cache.fetch(
        cache_key,
        expires_in: CACHE_TTL,
        force: refresh_cache?,
        skip_nil: skip_caching_failed_fetch?
      ) do
        fetch_total_credits
      end
    end

    def refresh_cache?
      cache_mode == :refresh
    end

    def skip_caching_failed_fetch?
      true
    end

    def fetch_total_credits
      client = ::Gitlab::SubscriptionPortal::SubscriptionUsageClient.new(namespace_id: namespace_id)
      response = client.get_monthly_commitment

      return unless response[:success]

      response.dig(:monthlyCommitment, :totalCredits) || 0
    end

    def cache_key
      "gitlab_subscriptions:monthly_commitment:#{namespace_id}"
    end
  end
end
