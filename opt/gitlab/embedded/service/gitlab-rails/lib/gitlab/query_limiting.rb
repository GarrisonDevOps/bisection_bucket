# frozen_string_literal: true

module Gitlab
  module QueryLimiting
    COUNTING_SKIPPED_KEY = :gitlab_query_limiting_counting_skipped

    # Returns true if we should enable tracking of query counts.
    #
    # This is only enabled in development and test to ensure we don't produce
    # any errors that users of other environments can't do anything about themselves.
    def self.enabled_for_env?
      Rails.env.development? || Rails.env.test?
    end

    def self.enabled?
      enabled_for_env? && !@suppressed
    end

    def self.threshold
      Gitlab::SafeRequestStore[:query_limiting_override_threshold]
    end

    # Process-wide. Turns off the request limit on every thread. Does not affect QueryRecorder.
    # To exclude specific amortized queries, see .without_counting.
    def self.with_suppressed_globally
      prev_value = @suppressed
      @suppressed = true

      yield
    ensure
      @suppressed = prev_value
    end

    # Thread-local. Excludes queries from the request limit and QueryRecorder.
    # To turn off limits across all threads in test harnesses, see .with_suppressed_globally.
    def self.without_counting
      previous = Thread.current[COUNTING_SKIPPED_KEY]
      Thread.current[COUNTING_SKIPPED_KEY] = true

      yield
    ensure
      Thread.current[COUNTING_SKIPPED_KEY] = previous
    end

    def self.counting_skipped?
      Thread.current[COUNTING_SKIPPED_KEY] == true
    end

    # Allows the current request to execute a higher number of SQL queries.
    #
    # This method should _only_ be used when there's a corresponding issue to
    # reduce the number of queries.
    #
    # The issue URL is only meant to push developers into creating an issue
    # instead of blindly disabling for offending blocks of code.
    #
    # The new_threshold is so that we don't allow unlimited number of SQL
    # queries while the issue is being fixed.
    def self.disable!(issue_url, new_threshold: 200)
      raise ArgumentError, 'new_threshold cannot exceed 2_000' unless new_threshold < 2_000

      unless issue_url.start_with?('https://')
        raise(
          ArgumentError,
          'You must provide a valid issue URL in order to allow a block of code'
        )
      end

      Gitlab::SafeRequestStore[:query_limiting_override_threshold] = new_threshold
    end

    # Enables query limiting for the request.
    def self.enable!
      Gitlab::SafeRequestStore[:query_limiting_override_threshold] = nil
    end
  end
end
