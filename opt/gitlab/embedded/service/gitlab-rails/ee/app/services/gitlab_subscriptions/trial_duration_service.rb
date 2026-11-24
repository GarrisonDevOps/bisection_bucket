# frozen_string_literal: true

module GitlabSubscriptions
  class TrialDurationService
    CACHE_EXPIRY = 1.hour
    FAILURE_CACHE_EXPIRY = 5.minutes
    CACHE_RACE_CONDITION_TTL = 1.minute
    CACHE_KEY = 'gitlab_subscriptions_trial_duration_service'
    FAIL_FAST_REQUEST_OPTIONS = { timeout: 1.second, max_retries: 0 }.freeze

    DEFAULT_DURATIONS = {
      GitlabSubscriptions::Trials::FREE_TRIAL_TYPE => { duration_days: 30 },
      GitlabSubscriptions::Trials::FREE_TRIAL_TYPE_V2 => { duration_days: 30 },
      GitlabSubscriptions::Trials::PREMIUM_TRIAL_TYPE => { duration_days: 30 },
      GitlabSubscriptions::Trials::PREMIUM_TRIAL_TYPE_V2 => { duration_days: 30 }
    }.freeze

    attr_reader :trial_type

    def initialize(trial_type = GitlabSubscriptions::Trials::FREE_TRIAL_TYPE_V2)
      @trial_type = trial_type
    end

    def execute
      return unless ::Gitlab::Saas.feature_available?(:subscriptions_trials)

      duration = find_trial_types[trial_type] || DEFAULT_DURATIONS[trial_type]
      return duration_days(duration) if duration

      Gitlab::AppLogger.warn(
        class: self.class.name,
        message: "The #{trial_type} trial type is not defined"
      )

      nil # This is a signal we do not have the trial_type defined in the DEFAULT_DURATIONS
    end

    private

    def find_trial_types
      Rails.cache.fetch(CACHE_KEY, **cache_options) do |_key, options|
        trial_types_request(options)
      end || {}
    end

    def cache_options
      return { expires_in: CACHE_EXPIRY } unless fail_fast?

      { expires_in: CACHE_EXPIRY, race_condition_ttl: CACHE_RACE_CONDITION_TTL }
    end

    def request_options
      fail_fast? ? FAIL_FAST_REQUEST_OPTIONS : {}
    end

    def fail_fast?
      Feature.enabled?(:fail_fast_cdot_trial_requests, Feature.current_request)
    end

    def duration_days(duration)
      return duration[:duration_days] unless duration[:next_active_time]
      return duration[:duration_days] if Time.zone.parse(duration[:next_active_time]).future?

      duration[:next_duration_days]
    rescue ArgumentError, TypeError
      duration[:duration_days]
    end

    def client
      Gitlab::SubscriptionPortal::Client
    end

    def trial_types_request(cache_write_options)
      response = client.namespace_trial_types(**request_options)

      if response[:success]
        response.dig(:data, :trial_types)
      else
        Gitlab::AppLogger.warn(
          class: self.class.name,
          message: 'Unable to fetch trial types from GitLab Customers App',
          error_message: response.dig(:data, :errors)
        )

        cache_write_options.expires_in = FAILURE_CACHE_EXPIRY if fail_fast?

        {}
      end
    end
  end
end
