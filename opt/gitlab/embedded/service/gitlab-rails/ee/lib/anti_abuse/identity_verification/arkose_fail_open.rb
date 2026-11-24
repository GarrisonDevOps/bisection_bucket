# frozen_string_literal: true

module AntiAbuse
  module IdentityVerification
    # Track Arkose token verification results for the current BUCKET_DURATION_HOURS window (00-03:59, 04:00-07:59, ...).
    # This data will be used later to track token verification rate per BUCKET_DURATION_HOURS window.
    module ArkoseFailOpen
      extend self

      BUCKET_DURATION_HOURS = 4
      BUCKET_DURATION_SECONDS = BUCKET_DURATION_HOURS.hours.to_i

      # Store 30 days of verification rate history for baseline smoothing.
      # Tunable if shorter or longer history proves better.
      VERIFICATION_RATE_HISTORY_DAYS = 30
      MAX_VERIFICATION_RATE_STREAM_ENTRIES = VERIFICATION_RATE_HISTORY_DAYS * (24 / BUCKET_DURATION_HOURS)
      MIN_ATTEMPTS_FOR_EVALUATION = 400
      MIN_BASELINE_COUNT = 10
      FAIL_OPEN_TTL_SECONDS = 30.minutes.to_i

      COUNTER_SUCCESS_KEY_PREFIX = 'arkose:token_verification:success:'
      COUNTER_FAILURE_KEY_PREFIX = 'arkose:token_verification:failure:'
      VERIFICATION_RATE_STREAM_KEY = 'arkose:token_verification:rates'
      FAIL_OPEN_ACTIVE_KEY = 'arkose:fail_open:active'

      def active?
        fail_open_active?
      end

      def track_token_verification_result(success:)
        evaluate_previous_window! if in_new_window?

        prefix = success ? COUNTER_SUCCESS_KEY_PREFIX : COUNTER_FAILURE_KEY_PREFIX
        increment_counter!(prefix)
      rescue Redis::BaseError => e
        Gitlab::ErrorTracking.track_exception(e)
      end

      private

      def evaluate_previous_window!
        verification_rate = calculate_verification_rate

        return unless verification_rate.present?

        baseline_values = historical_verification_rates
        decision = ArkoseAnomalyDetection::Decision.new(anomalous: false, reason: 'insufficient data')

        if baseline_values.size >= MIN_BASELINE_COUNT
          decision = ArkoseAnomalyDetection.decide(
            current_value: verification_rate,
            baseline_values: baseline_values
          )
        end

        # IMPORTANT: do not append anomalous verification rate to baseline as this will 'poison' the baseline
        trigger_fail_open(decision) if decision.anomalous
        record_verification_rate(verification_rate) unless decision.anomalous
      end

      def in_new_window?
        # If we haven't started counting for the current window then we're in a new window
        with_redis do |r|
          success_exists = r.exists(bucket_counter_key(COUNTER_SUCCESS_KEY_PREFIX)) > 0
          failure_exists = r.exists(bucket_counter_key(COUNTER_FAILURE_KEY_PREFIX)) > 0
          !(success_exists || failure_exists)
        end
      end

      def calculate_verification_rate(log: true)
        prev_id = previous_bucket_id
        success = counter_value(prefix: COUNTER_SUCCESS_KEY_PREFIX, bucket_id: prev_id)
        failure = counter_value(prefix: COUNTER_FAILURE_KEY_PREFIX, bucket_id: prev_id)
        total   = success + failure
        rate_percentage = token_verification_rate(success, total)

        if log
          Gitlab::AppLogger.info(
            message: 'Arkose token verification rate',
            bucket: prev_id,
            success_count: success,
            failure_count: failure,
            total_count: total,
            rate: rate_percentage
          )
        end

        # SCENARIO: Insufficient recorded verification results in the previous bucket.
        # - Could be no traffic, feature just enabled, Arkose disabled, or fail-open active.
        # ACTION: Do not record verification rate.
        return if total < MIN_ATTEMPTS_FOR_EVALUATION

        rate_percentage
      end

      def trigger_fail_open(decision)
        Gitlab::AppLogger.warn(
          message: 'Activated fail-open due to anomaly detected',
          prev_bucket: previous_bucket_id,
          reason: decision.reason
        )

        activate_fail_open!(reason: decision.reason)
      end

      def increment_counter!(prefix)
        key = bucket_counter_key(prefix)
        with_redis do |redis|
          redis.multi do |transaction|
            transaction.incr(key)

            # NOTE: We are only interested in token verification request result counters in the current window
            # so we let counters older than two windows expire.
            transaction.expire(key, BUCKET_DURATION_SECONDS * 2, nx: true)
          end
        end
      end

      # NOTE: bucket_counter_keys look like "arkose:token_verification:success:{BUCKET_ID_HERE}"
      def bucket_counter_key(prefix, at: Time.zone.now)
        "#{prefix}#{bucket_id(at: at)}"
      end

      def previous_bucket_id(at: Time.zone.now)
        bucket_id(at: at - BUCKET_DURATION_SECONDS)
      end

      # NOTE: A bucket id is comprised of the current date and the number of the bucket.
      # E.g. 00:00-03:59 bucket will have bucket id 20240612-0, 04:00-07:59 20240612-1 and so on.
      def bucket_id(at: Time.zone.now)
        date_str     = at.strftime('%Y%m%d')
        bucket_index = at.hour / BUCKET_DURATION_HOURS
        "#{date_str}-#{bucket_index}"
      end

      def token_verification_rate(successes, attempts)
        return 0.0 if attempts.to_f <= 0.0

        (successes.to_f / attempts) * 100.0
      end

      def counter_value(prefix:, bucket_id:)
        key = "#{prefix}#{bucket_id}"
        with_redis { |r| r.get(key).to_i }
      end

      def record_verification_rate(rate_percentage)
        fields = { 'bucket' => previous_bucket_id, 'vrate' => rate_percentage.to_s }
        with_redis do |r|
          r.xadd(
            VERIFICATION_RATE_STREAM_KEY,
            fields,
            maxlen: MAX_VERIFICATION_RATE_STREAM_ENTRIES,
            approximate: true
          )
        end
      end

      def historical_verification_rates
        with_redis { |r| r.xrange(VERIFICATION_RATE_STREAM_KEY, '-') }
          .filter_map { |_, fields| fields['vrate']&.to_f }
      end

      def activate_fail_open!(reason:)
        with_redis { |r| r.set(FAIL_OPEN_ACTIVE_KEY, reason, ex: FAIL_OPEN_TTL_SECONDS) }
      end

      def fail_open_active?
        with_redis { |r| r.exists?(FAIL_OPEN_ACTIVE_KEY) } # rubocop:disable CodeReuse/ActiveRecord -- Redis access is required here; not an AR model
      end

      def with_redis
        ::Gitlab::Redis::SharedState.with { |r| yield r }
      end
    end
  end
end
