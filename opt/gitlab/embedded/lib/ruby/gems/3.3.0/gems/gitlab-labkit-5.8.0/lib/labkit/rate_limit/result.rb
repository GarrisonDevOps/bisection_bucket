# frozen_string_literal: true

require "time" # Time#httpdate

module Labkit
  module RateLimit
    # Result is the return value of Limiter#check.
    #
    # It accumulates one Result::Evaluation per matched-and-counted rule; the
    # reader methods report the single most-constraining evaluation (see
    # #most_constraining). A matched :skip rule or a fail-open error replaces
    # the evaluations as the source of the reported outcome.
    #
    # Result is a mutable accumulator, not a value object: two Results built
    # from the same evaluations are not #==.
    #
    # matched?    - true if at least one rule's match conditions were satisfied
    # exceeded?   - true if the reported evaluation's counter exceeded its limit
    # action      - the outcome: what the caller should do
    #               :block = a :limit rule matched and is over its limit
    #               :allow = everything else, including an exceeded :log rule
    #               (visible via exceeded?), a matched :skip rule, no rule
    #               matched, and error (fail-open).
    #               The rule's configured action is available via rule.action.
    # rule        - the reported Rule: the :skip rule when one matched, otherwise
    #               the most-constraining evaluated Rule (nil when matched? is
    #               false). Other rules may also have matched and been counted;
    #               see #evaluations.
    # error?      - true if Redis was unavailable; result fails open (exceeded? is false)
    # degraded?   - true if a matched count_distinct rule was skipped by the
    #               missing-key fail-open path; the check still completed
    # info        - Result::Info with per-window counters for the reported rule;
    #               nil when matched? is false, error?, or the matched rule is
    #               :skip (no counter exists)
    # evaluations - every counted evaluation, in rule declaration order
    class Result
      attr_reader :evaluations

      def self.error
        new(error: true)
      end

      def initialize(error: false)
        @evaluations = []
        @skip_rule = nil
        @error = error
        @degraded = false
        @most_constraining = nil
      end

      def add_evaluation(evaluation)
        @most_constraining = nil
        @evaluations << evaluation
        self
      end

      # Records a matched :skip rule: the request is allowed and the skip rule
      # is the one reported, regardless of any evaluations already collected.
      def skip!(rule)
        @skip_rule = rule
        self
      end

      def matched?
        skipped? || @evaluations.any?
      end

      def skipped?
        !!@skip_rule
      end

      def block?
        !skipped? && @evaluations.any?(&:block?)
      end

      def exceeded?
        return false if skipped?

        !most_constraining.nil? && most_constraining.exceeded?
      end

      def error?
        @error
      end

      # Unlike error?, the check keeps going: the flag marks the outcome as
      # degraded without changing it.
      def degraded!
        @degraded = true
        self
      end

      def degraded?
        @degraded
      end

      def action
        block? ? :block : :allow
      end

      def rule
        @skip_rule || most_constraining&.rule
      end

      def info
        return nil if skipped?

        most_constraining&.info
      end

      # The evaluation with the strongest claim on the outcome; ties keep the
      # earliest-declared rule (min returns the first of tied elements).
      # Memoized; add_evaluation invalidates.
      def most_constraining
        @most_constraining ||= @evaluations.min
      end

      # Returns the rate limit response headers of the most constraining
      # evaluation, or {} when no rule matched, a :skip rule matched, or an
      # error occurred. See Result::Evaluation#to_response_headers for the keys.
      def to_response_headers
        return {} unless matched? && !error? && info

        most_constraining.to_response_headers
      end
    end

    # The outcome of counting one matched rule.
    # rule     - the evaluated Rule
    # exceeded - whether the post-increment count exceeded the resolved limit
    # info     - Result::Info with the per-window counters
    #
    # Evaluations order by constraint: a blocking evaluation (a :limit rule over
    # its limit, or one whose ban is still in force) ranks strictly first - it
    # decides the request no matter what any other rule reports - then exceeded
    # ones, then fewest remaining.
    # remaining floors at 0, so an exceeded :log rule ties with one sitting
    # exactly on its limit; ranking exceeded ahead keeps a breach from being
    # hidden by a rule that merely reached its limit.
    Result::Evaluation = Data.define(:rule, :exceeded, :info) do
      include Comparable

      def exceeded?
        exceeded
      end

      def block?
        exceeded? && rule.action == :limit
      end

      def <=>(other)
        constraint_rank <=> other.constraint_rank
      end

      # Returns the rate limit response headers for this evaluation. Values are
      # Strings, and counts are coerced to Integer because the RateLimit header
      # spec requires integer values even when count is fractional.
      #
      # RateLimit-Name (the rule name), RateLimit-Limit, RateLimit-Observed,
      # RateLimit-Remaining and RateLimit-Reset (Unix timestamp) are always
      # present. Limit, Observed and Remaining all count within the rule's own
      # period. A blocking evaluation also gets Retry-After (seconds) and
      # RateLimit-ResetTime (HTTP date), which belong on the 429.
      def to_response_headers
        headers = {}
        headers["RateLimit-Name"] = rule.name
        # Floored at 0 like remaining: a callable limit can resolve below zero
        # to deny all, and an older client could credit a counter below zero.
        headers["RateLimit-Limit"] = [info.resolved_limit.to_i, 0].max.to_s
        headers["RateLimit-Observed"] = [info.count.to_i, 0].max.to_s
        headers["RateLimit-Remaining"] = info.remaining.to_i.to_s
        headers["RateLimit-Reset"] = info.reset_at.to_i.to_s
        return headers unless block?

        # Rounded up so a client that honours it does not retry before the reset.
        headers["Retry-After"] = [(info.reset_at - Time.now.utc).ceil, 0].max.to_s
        headers["RateLimit-ResetTime"] = info.reset_at.httpdate
        headers
      end

      protected

      def constraint_rank
        [block? ? 0 : 1, exceeded? ? 0 : 1, info.remaining]
      end
    end

    # Per-window counter data attached to a matched Result.
    # resolved_limit  - the evaluated limit Integer for this rule
    # resolved_period - the evaluated period Integer (seconds) for this rule
    # count           - the post-increment counter value as a Float; integer-valued
    #                   for default cost=1 callers, fractional for cost-mode callers.
    #                   Pre-2.x releases exposed this as Integer; see the migration
    #                   note in the cost-aware Lua script change.
    # remaining       - requests remaining before the limit is hit, clamped to
    #                   [0, resolved_limit]; 0 throughout when the limit is
    #                   non-positive. Inherits Float typing from count when
    #                   count is fractional.
    # reset_at        - best-effort UTC Time when the counter window resets
    Result::Info = Data.define(:resolved_limit, :resolved_period, :count, :remaining, :reset_at)
  end
end
