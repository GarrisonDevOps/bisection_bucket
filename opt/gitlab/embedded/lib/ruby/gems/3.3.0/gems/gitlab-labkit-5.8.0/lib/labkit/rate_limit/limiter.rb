# frozen_string_literal: true

require "labkit/logging/json_logger"

module Labkit
  module RateLimit
    # Limiter is the primary public API for rate limiting.
    # Instantiate once per call site (e.g. at application boot), then call
    # #check(identifier) on every request. The internal Evaluator is reused
    # across calls, avoiding per-request object allocation.
    #
    # @example
    #   limiter = Labkit::RateLimit::Limiter.new(
    #     name: "rack_request",
    #     rules: [Labkit::RateLimit::Rule.new(name: "api_user", limit: 100, period: 60, characteristics: [:user])]
    #   )
    #   result = limiter.check({ user: 42, ip: "1.2.3.4" })
    #   render_429 if result.action == :block
    class Limiter
      NAME_PATTERN = /\A[a-z0-9_]+\z/

      def initialize(name:, rules:, redis: nil, logger: nil)
        @logger = logger || RateLimit.config.logger || Labkit::Logging::JsonLogger.new($stdout)
        @name = validate_name!(name)

        @evaluator = Evaluator.new(
          name: @name,
          rules: prepare_rules(rules),
          redis: redis || RateLimit.config.redis,
          logger: @logger
        )
      end

      # @param identifier [Identifier, Hash] caller attributes for this request
      # @param cost [Numeric] amount to add to the counter. Defaults to 1
      #   (count-mode). Pass a non-1 Numeric for cost-mode counters such as
      #   resource-usage limits; passing 0 reads the counter without writing.
      #   A negative cost would credit quota back, so the check fails open and
      #   logs instead of counting.
      # @param rule_context [Hash, nil] optional per-request context passed to
      #   one-arity callables on +limit+/+period+. Lets rules resolve dynamic
      #   configuration (e.g. per-namespace settings) without rebuilding the
      #   Rule or doing out-of-band DB queries. Zero-arity callables ignore it.
      #   The key contract is owned by the rule's callable, not validated
      #   here: if the rule reads ctx[:limit] and the caller passes
      #   ctx[:lmit], the callable's fallback branch fires silently. Keep
      #   the rule definition and the call site colocated.
      # @return [Result]
      def check(identifier, cost: 1, rule_context: nil)
        id = to_identifier(identifier)
        @evaluator.check(id, cost: cost, rule_context: rule_context)
      end

      # Read the current rate-limit state without incrementing the counter.
      # Mirrors {#check} except the underlying counter is not mutated and the
      # TTL is not extended. Useful for "have we already throttled this caller?"
      # checks where the caller has another path that does the actual increment
      # (typical pattern: peek to gate a side-effect, then call #check on the
      # path that should count).
      #
      # When the underlying Redis key does not exist yet, the result reports
      # count=0, exceeded=false, and remaining=resolved_limit; matched? is
      # still true because the rule applied. On Redis error the result fails
      # open identically to {#check}.
      #
      # @param identifier [Identifier, Hash] caller attributes for this request
      # @param rule_context [Hash, nil] see {#check}
      # @return [Result]
      def peek(identifier, rule_context: nil)
        id = to_identifier(identifier)
        @evaluator.peek(id, rule_context: rule_context)
      end

      # Discards this limiter's state for one identifier: every rule's counter,
      # and any ban written by a rule carrying ban_for.
      #
      # For call sites where a later success should wipe earlier failures, such
      # as an authentication ban cleared by a valid login. Counters otherwise
      # only expire with their window; this is the only way to end one early.
      #
      # Scoped to this limiter and identifier, not to a single rule: a caller
      # clearing after a success knows who succeeded, not which rules matched.
      #
      # @param identifier [Identifier, Hash] caller attributes
      # @return [Integer] number of Redis keys removed; on a Redis error, those
      #   removed before it failed
      def clear(identifier)
        @evaluator.clear(to_identifier(identifier))
      end

      private

      def to_identifier(identifier)
        identifier.is_a?(Identifier) ? identifier : Identifier.new(identifier)
      end

      def validate_name!(name)
        raise ArgumentError, "name must be a non-empty String" unless name.is_a?(String) && !name.empty?
        return name if NAME_PATTERN.match?(name)

        raise ArgumentError, "Invalid name: #{name.inspect}. Must match /\\A[a-z0-9_]+\\z/" if Labkit.dev_or_test?

        sanitized = name.gsub(/[^a-z0-9_]/, "_")
        @logger.warn(message: "rate_limit_invalid_name", name: name, sanitized: sanitized)
        sanitized
      end

      # Validates and deduplicates rule names before passing rules to Evaluator.
      # In dev/test: raises on invalid format or duplicate names.
      # In production: sanitizes invalid names (WARN) and drops duplicates (WARN, first wins).
      # Returns an array of rules with sanitized names.
      def prepare_rules(rules)
        seen = {}
        rules.each_with_index.filter_map do |rule, idx|
          sanitized = sanitize_rule_name(rule.name)

          if seen.key?(sanitized)
            raise ArgumentError, "Duplicate rule name #{sanitized.inspect} at index #{idx}" if Labkit.dev_or_test?

            @logger.warn(
              message: "rate_limit_duplicate_rule_name",
              name: sanitized,
              dropped_occurrence: idx
            )
            next nil
          end

          seen[sanitized] = true
          sanitized == rule.name ? rule : rule.with(name: sanitized) # rubocop:disable CodeReuse/ActiveRecord
        end
      end

      def sanitize_rule_name(name)
        s = name.to_s
        return s if RULE_NAME_PATTERN.match?(s) && s.length <= RULE_NAME_MAX_LENGTH

        sanitized = s.downcase.gsub(/[^a-z0-9_]/, "_")[0, RULE_NAME_MAX_LENGTH]
        sanitized = "unnamed_rule" if sanitized.empty?
        @logger.warn(
          message: "rate_limit_invalid_rule_name",
          original_name: s,
          sanitized_name: sanitized
        )
        sanitized
      end
    end
  end
end
