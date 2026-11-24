# frozen_string_literal: true

module Labkit
  # RateLimit provides a rules-based rate limiting API backed by Redis counters.
  # Primary usage: instantiate a Limiter once per call site and reuse it.
  #
  # @example Configuration (e.g. in a Rails initializer)
  #   Labkit::RateLimit.configure do |c|
  #     c.redis  = ConnectionPool.new { Redis.new }  # must respond to .with { |conn| }
  #     c.logger = Labkit::Logging::JsonLogger.new($stdout)
  #   end
  #
  # @example Per-call-site setup
  #   RACK_LIMITER = Labkit::RateLimit::Limiter.new(
  #     name: "rack_request",
  #     rules: [...]
  #   )
  #   result = RACK_LIMITER.check(identifier)
  module RateLimit
    autoload :Configuration, "labkit/rate_limit/configuration"
    autoload :Identifier, "labkit/rate_limit/identifier"
    autoload :Matcher, "labkit/rate_limit/matcher"
    autoload :Result, "labkit/rate_limit/result"
    autoload :Rule, "labkit/rate_limit/rule"
    autoload :Evaluator, "labkit/rate_limit/evaluator"
    autoload :Limiter, "labkit/rate_limit/limiter"
    autoload :Metrics, "labkit/rate_limit/metrics"
    autoload :BlockSummary, "labkit/rate_limit/block_summary"

    class << self
      def configure
        yield config
      end

      def config
        @config ||= Configuration.new
      end

      # Convenience wrapper - creates a throw-away Limiter.
      # Prefer Limiter for call sites that can cache the object.
      #
      # @param name [String] call site name
      # @param identifier [Identifier, Hash] caller attributes
      # @param rules [Array<Rule>] ordered list of rules; every matching rule is
      #   counted, and the Result reports the most constraining one
      # @param redis [Object, nil] Redis client; falls back to config.redis
      # @param logger [Logger, nil] logger; falls back to config.logger
      # @param cost [Numeric] amount to add to the counter; see Limiter#check
      # @param rule_context [Hash, nil] per-request context for one-arity
      #   callables on rule limit/period; see Limiter#check
      # @return [Result]
      def check(name:, identifier:, rules:, redis: nil, logger: nil, cost: 1, rule_context: nil)
        Limiter.new(name: name, rules: rules, redis: redis, logger: logger)
          .check(identifier, cost: cost, rule_context: rule_context)
      end
    end
  end
end
