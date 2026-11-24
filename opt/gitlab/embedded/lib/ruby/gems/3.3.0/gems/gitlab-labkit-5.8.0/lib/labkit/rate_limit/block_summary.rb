# frozen_string_literal: true

module Labkit
  module RateLimit
    # Counts blocks per (endpoint_id, rule) in this process and logs the counts
    # every interval. A line per block grows with an attack, so lines here grow
    # only with the number of distinct pairs this process blocked, and never past
    # max_pairs + 1.
    #
    # One line per pair rather than one line holding a map: map keys become
    # index fields, one per endpoint name. The fields are rate_limit_rule and
    # block_count, not rule and count, so they cannot clash with another line's
    # type for a common name in a shared index.
    #
    # The caller owns the thread: run #call on one, and #stop it on shutdown so
    # the last counts are flushed.
    class BlockSummary
      MESSAGE = "rate_limit_block_summary"
      OTHER = "other"
      OTHER_KEY = [OTHER, OTHER].freeze
      DEFAULT_INTERVAL_SECONDS = 300
      DEFAULT_MAX_PAIRS = 10

      def initialize(logger: nil, interval: DEFAULT_INTERVAL_SECONDS, max_pairs: DEFAULT_MAX_PAIRS)
        # A zero interval would make #call spin without waiting.
        raise ArgumentError, "interval must be a positive Numeric, got #{interval.inspect}" unless interval.is_a?(Numeric) && interval.positive?

        raise ArgumentError, "max_pairs must be a positive Integer, got #{max_pairs.inspect}" unless max_pairs.is_a?(Integer) && max_pairs.positive?

        @logger = logger || RateLimit.config.logger || Labkit::Logging::JsonLogger.new($stdout)
        @interval = interval
        @max_pairs = max_pairs
        @counts = {}
        @mutex = Mutex.new
        @stop_signal = Thread::Queue.new
      end

      # Keyed on the pair alone, so feature_category never adds a line. The first
      # non-nil one passed for a pair is kept. Capped here rather than at flush,
      # so the hash cannot grow during an attack.
      def add(endpoint_id:, rule:, feature_category: nil)
        key = [endpoint_id, rule]

        @mutex.synchronize do
          key = OTHER_KEY if !@counts.key?(key) && pairs_full?
          entry = (@counts[key] ||= [0, nil])
          entry[0] += 1
          entry[1] ||= feature_category unless key == OTHER_KEY
        end
      end

      # Waits on a queue rather than sleeping, so a stop that lands mid-flush is
      # still seen and the final flush is never skipped. The first wait is
      # random, so workers booted together do not all flush at once.
      def call
        timeout = rand * @interval

        loop do
          stopping = @stop_signal.pop(timeout: timeout)
          flush
          break if stopping

          timeout = @interval
        end
      end

      # Only signals #call, which runs the final flush. Without a thread in #call,
      # nothing is flushed.
      def stop
        @stop_signal << true
      end

      def flush
        drained = {}
        logged = 0

        drained = @mutex.synchronize do
          counts = @counts
          @counts = {}
          counts
        end

        drained.each do |(endpoint_id, rule), (count, feature_category)|
          @logger.info(line(endpoint_id, rule, feature_category, count))
          logged += 1
        end
      rescue StandardError => e
        log_failure(e, drained.size - logged)
      end

      private

      def pairs_full?
        @counts.size - (@counts.key?(OTHER_KEY) ? 1 : 0) >= @max_pairs
      end

      def line(endpoint_id, rule, feature_category, count)
        payload = { message: MESSAGE, Labkit::Fields::ENDPOINT_ID => endpoint_id, rate_limit_rule: rule, block_count: count }
        payload[:feature_category] = feature_category if feature_category
        payload
      end

      # Never raises: a raise here would kill the caller's flush thread.
      # The counts are already drained, so dropped_pairs says how many lines
      # this flush lost.
      def log_failure(error, dropped_pairs)
        @logger.warn(
          message: "rate_limit_error",
          Labkit::Fields::ERROR_TYPE => "rate_limit_error",
          Labkit::Fields::CLASS_NAME => error.class.to_s,
          Labkit::Fields::ERROR_MESSAGE => error.message,
          dropped_pairs: dropped_pairs
        )
      rescue StandardError
        nil
      end
    end
  end
end
