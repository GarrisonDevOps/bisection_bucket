# frozen_string_literal: true

require "openssl"

module Labkit
  module RateLimit
    # Evaluator holds the static parts of a rate limit check (name, rules, Redis)
    # and exposes a per-request #check(identifier) method.
    # @api private
    class Evaluator
      REDIS_KEY_PREFIX = "labkit:rl"
      BAN_KEY_SUFFIX = ":ban"
      CHAR_VALUE_MAX_LENGTH = 200
      MISSING_VALUE_SENTINEL = "_unknown_"

      # Carries the rule in flight out of the rule loop and into the rescue in
      # #check/#peek, where the error is seen but the rule is out of scope.
      # Per call, not instance state: one Evaluator serves concurrent requests.
      # Only read while an exception unwinds; nil means no rule was in flight.
      RuleCursor = Struct.new(:rule)

      # Atomic increment-with-TTL Lua script. The whole script runs as one
      # operation from Redis's perspective, so there is no window between
      # the increment and EXPIRE that can leak a key without TTL.
      #
      # INCRBYFLOAT serves both count-mode (cost=1, equivalent to INCR for
      # integer-encoded keys) and cost-mode callers, so a single script
      # handles every rule shape. cost=0 also flows through INCRBYFLOAT;
      # Redis treats the result as a no-op on the stored value while
      # still observing the post-state count and TTL we return.
      #
      # ttl_after < 0 covers TTL=-2 (key missing) and TTL=-1 (no expiry).
      # The -1 case shouldn't arise with the atomic script, but self-healing
      # recovers keys left without TTL by any prior bug.
      INCR_SCRIPT = Labkit::Redis::Script.new(<<~LUA)
        local ttl = ARGV[1]
        local cost = tonumber(ARGV[2])

        local count = redis.call('INCRBYFLOAT', KEYS[1], cost)
        local ttl_after = redis.call('TTL', KEYS[1])
        if ttl_after < 0 then
          redis.call('EXPIRE', KEYS[1], ttl)
          ttl_after = tonumber(ttl)
        end

        return {count, ttl_after}
      LUA

      # Atomic SADD + SCARD + conditional EXPIRE. SET-cardinality counterpart
      # of INCR_SCRIPT; same shape (mutate, read TTL, set TTL when missing,
      # return post-state {count, TTL}). count is SCARD, not the SADD return.
      #
      # ttl_after < 0 covers TTL=-2 (key missing) and TTL=-1 (no expiry),
      # so this also self-heals orphan keys left without TTL.
      SADD_SCRIPT = Labkit::Redis::Script.new(<<~LUA)
        local ttl = ARGV[1]
        local member = ARGV[2]

        redis.call('SADD', KEYS[1], member)
        local count = redis.call('SCARD', KEYS[1])
        local ttl_after = redis.call('TTL', KEYS[1])
        if ttl_after < 0 then
          redis.call('EXPIRE', KEYS[1], ttl)
          ttl_after = tonumber(ttl)
        end

        return {count, ttl_after}
      LUA

      # Atomic ban check + INCR + conditional ban write, for rules carrying
      # ban_for.
      #
      # An active ban short-circuits before the increment, so a banned caller
      # cannot extend its own window, matching Rack::Attack::Allow2Ban. This
      # applies to :log rules too: a shadow that kept counting through its own
      # ban would report more than enforcement would produce. The
      # counter and the ban must be read and written together or a concurrent
      # check can miss the threshold crossing.
      #
      # Returns {count, counter TTL, ban TTL}, where a ban TTL below zero means
      # not banned.
      BAN_SCRIPT = Labkit::Redis::Script.new(<<~LUA)
        local rule_counter_key = KEYS[1]
        local ban_key = KEYS[2]

        local ttl = ARGV[1]
        local cost = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        local ban_for = tonumber(ARGV[4])

        -- TTL answers both questions at once: >= 0 means the ban key exists
        -- and tells us how long is left, so no separate EXISTS is needed.
        local ban_ttl = redis.call('TTL', ban_key)
        if ban_ttl >= 0 then
          local existing = redis.call('GET', rule_counter_key)
          return {existing or '0', redis.call('TTL', rule_counter_key), ban_ttl}
        end

        local count = redis.call('INCRBYFLOAT', rule_counter_key, cost)
        local ttl_after = redis.call('TTL', rule_counter_key)
        if ttl_after < 0 then
          redis.call('EXPIRE', rule_counter_key, ttl)
          ttl_after = tonumber(ttl)
        end

        if tonumber(count) > limit then
          redis.call('SET', ban_key, '1', 'EX', ban_for)
          return {count, ttl_after, ban_for}
        end

        return {count, ttl_after, -1}
      LUA

      def initialize(name:, rules:, redis:, logger:)
        @name   = name
        @rules  = rules
        @redis  = redis
        @logger = logger
      end

      def check(identifier, cost: 1, rule_context: nil)
        cursor = RuleCursor.new
        # A negative cost would credit quota back and open the window for good.
        raise ArgumentError, "cost is #{cost}, must not be negative" if cost.negative?

        result = check_rules(identifier, cost, rule_context, cursor)
      rescue StandardError => e
        # Intentionally broad: fail-open applies to any unexpected error (network,
        # timeout, OOM) not only Redis protocol errors.
        log_error(e, identifier, cursor.rule)
        result = Result.error
      ensure
        # StandardError-safe emission, so it cannot mask a propagating error.
        # result is nil when a non-StandardError unwinds: emit nothing then.
        report_check_metrics(result) if result
      end

      # Read-without-increment counterpart to {#check}. Same matching and Result
      # shape; the underlying Redis counter is not mutated and the TTL is not
      # extended. A missing Redis key is treated as count=0 (matched, not exceeded).
      def peek(identifier, rule_context: nil)
        cursor = RuleCursor.new
        result = peek_rules(identifier, rule_context, cursor)
      rescue StandardError => e
        log_error(e, identifier, cursor.rule)
        result = Result.error
      ensure
        report_peek_metrics(result) if result
      end

      # Deletes this limiter's counters, and any bans, for one identifier.
      #
      # Every rule is cleared, matched or not: a caller clearing state after a
      # success knows the identifier, not which rules happened to match on the
      # way in. Rules whose keys do not exist are a no-op.
      #
      # Fails open like {#check}: an unreachable Redis leaves the state to
      # expire on its own rather than raising into the caller.
      def clear(identifier)
        # Counted as we go, so a connection lost mid-loop still reports the keys
        # that did go rather than claiming nothing was cleared.
        removed = 0

        key_groups = @rules.filter_map do |rule|
          next if rule.action == :skip

          [build_redis_key(rule, identifier), build_redis_key(rule, identifier, BAN_KEY_SUFFIX)]
        end

        return 0 if key_groups.empty?

        # One DEL per rule. The hash tag holds the rule name, so a rule's own
        # keys share a slot but two rules do not, and Redis Cluster rejects a
        # DEL spanning slots.
        @redis.with do |conn|
          key_groups.each { |group| removed += conn.del(*group) }
        end

        removed
      rescue StandardError => e
        log_error(e, identifier, nil)
        removed
      end

      private

      # Every rule that matches is evaluated and counted; matching does not
      # short-circuit the loop. Exactly two cases terminate it early:
      #
      # - :skip terminates on match without touching Redis. No counter is
      #   incremented, so the branch sits before the count_distinct check
      #   (identifier completeness is irrelevant to a rule that builds no key).
      #   rule_evaluations_total still increments so the bypass stays observable.
      # - a :limit rule over its limit terminates, because the request is
      #   rejected and later rules cannot change that. Rules declared after it
      #   are neither counted nor evaluated, so a blocked request debits every
      #   rule up to and including the one that blocked, and none after it.
      #   A :limit rule carrying ban_for counts as over its limit for as long
      #   as its ban holds, so it terminates for the whole ban. The same rule
      #   with action :log does identical accounting and terminates nothing,
      #   which is what makes it a faithful shadow.
      #
      # Every other matched rule - :log, and :limit while under its limit - is
      # counted and collected into the returned Result, which reports the
      # most-constraining evaluation (ranking lives in Result::Evaluation#<=>).
      # cost is therefore debited from every matching rule, not just the first.
      #
      # Metrics: each evaluated rule emits rule_evaluations_total; the per-check
      # checks_total is emitted once in #check. Full contract in the README's
      # Metrics section.
      #
      # SET-mode rules (rule.count_distinct set) that match but whose identifier
      # is missing the count_distinct key fail open + log + flag the Result, and
      # the loop continues to the next rule (the rule is treated as not
      # applicable rather than aborting the whole evaluation).
      #
      # Error handling stays whole-check (see #check): a raise part-way through
      # discards the results of the rules already evaluated, even though their
      # counters were incremented. No blocking verdict is lost that way - a
      # :limit rule over its limit returns before any later rule can raise -
      # but a rule declared after the failing one loses its chance to block.
      # The request is counted and allowed. +cursor+ is set before the match, so
      # a raise from the match itself (e.g. Regexp::TimeoutError) is attributed.
      def check_rules(identifier, cost, rule_context, cursor)
        result = Result.new

        @rules.each do |rule|
          cursor.rule = rule

          next unless rule_matches?(rule, identifier)

          if rule.action == :skip
            report_skipped_metrics(rule)
            return result.skip!(rule)
          end

          if rule.count_distinct && missing_count_distinct_value?(rule, identifier)
            log_missing_count_distinct(rule, identifier)
            result.degraded!
            next
          end

          evaluation = evaluate_rule(rule, identifier, cost, rule_context)
          result.add_evaluation(evaluation)
          report_evaluation_metrics(evaluation)
          return result if result.block?
        end

        # The loop is done, so anything raised from here on belongs to no rule.
        cursor.rule = nil

        result
      rescue StandardError => e # binds e for the ensure
        raise
      ensure
        # Keep the rule attributed while an exception unwinds; clear it on
        # every normal exit (early returns included).
        cursor.rule = nil unless e
      end

      # Mirror of check_rules without metrics or writes. :log rules are read
      # here too: check can report a :log rule's evaluation, so excluding them
      # would make peek answer a different question than check.
      #
      # peek does not need the count_distinct identifier key - it reads SCARD on
      # the rule-keyed compound key, which contains the cardinality across all
      # members. So missing-key fail-open does not apply here.
      def peek_rules(identifier, rule_context, cursor)
        result = Result.new

        @rules.each do |rule|
          cursor.rule = rule

          next unless rule_matches?(rule, identifier)

          return result.skip!(rule) if rule.action == :skip

          result.add_evaluation(peek_rule(rule, identifier, rule_context))
          return result if result.block?
        end

        result
      rescue StandardError => e # binds e for the ensure
        raise
      ensure
        cursor.rule = nil unless e
      end

      def rule_matches?(rule, identifier)
        rule.match.all? { |key, matcher| matcher.match?(identifier[key]) }
      end

      def missing_count_distinct_value?(rule, identifier)
        value = identifier[rule.count_distinct]
        value.nil? || value.to_s.empty?
      end

      def evaluate_rule(rule, identifier, cost, rule_context)
        return evaluate_ban_rule(rule, identifier, cost, rule_context) if rule.ban_for

        redis_key = build_redis_key(rule, identifier)
        resolved_limit = Integer(resolve_value(rule.limit, rule_context))
        resolved_period = Integer(resolve_value(rule.period, rule_context))

        # cost is ignored for count_distinct rules: SADD is binary (a member is
        # either added or not), and the post-add count is SCARD regardless.
        count, ttl =
          if rule.count_distinct
            sadd_with_ttl(redis_key, identifier[rule.count_distinct], resolved_period)
          else
            incr_with_ttl(redis_key, resolved_period, cost)
          end

        build_evaluation(rule, resolved_limit, resolved_period, count, ttl)
      end

      def peek_rule(rule, identifier, rule_context)
        return peek_ban_rule(rule, identifier, rule_context) if rule.ban_for

        redis_key = build_redis_key(rule, identifier)
        resolved_limit = Integer(resolve_value(rule.limit, rule_context))
        resolved_period = Integer(resolve_value(rule.period, rule_context))

        count, ttl = rule.count_distinct ? scard_with_ttl(redis_key) : read_with_ttl(redis_key)
        build_evaluation(rule, resolved_limit, resolved_period, count, ttl)
      end

      def evaluate_ban_rule(rule, identifier, cost, rule_context)
        resolved_limit = Integer(resolve_value(rule.limit, rule_context))
        resolved_period = Integer(resolve_value(rule.period, rule_context))
        resolved_ban_for = resolve_ban_for(rule, rule_context)

        count, ttl, ban_ttl = ban_incr_with_ttl(
          build_redis_key(rule, identifier),
          build_redis_key(rule, identifier, BAN_KEY_SUFFIX),
          resolved_period, cost, resolved_limit, resolved_ban_for
        )

        build_ban_evaluation(rule, resolved_limit, resolved_period, count, ttl, ban_ttl)
      end

      # A callable ban_for is only checked at construction, so it can still hand
      # back something Redis would reject on the SET that writes the ban. Failing
      # here names ban_for rather than surfacing a line number from the script.
      def resolve_ban_for(rule, rule_context)
        raw = resolve_value(rule.ban_for, rule_context)
        seconds = Integer(raw, exception: false)
        raise ArgumentError, "ban_for resolved to #{raw.inspect}, need at least 1 second" if seconds.nil? || seconds < 1

        seconds
      end

      def peek_ban_rule(rule, identifier, rule_context)
        resolved_limit = Integer(resolve_value(rule.limit, rule_context))
        resolved_period = Integer(resolve_value(rule.period, rule_context))

        count, ttl, ban_ttl = read_ban_with_ttl(
          build_redis_key(rule, identifier),
          build_redis_key(rule, identifier, BAN_KEY_SUFFIX)
        )

        build_ban_evaluation(rule, resolved_limit, resolved_period, count, ttl, ban_ttl)
      end

      # A ban blocks whether it was written by this call or an earlier one, so
      # +exceeded+ tracks the ban rather than the count: once the counter window
      # has expired the count can sit below the limit while the ban still holds.
      # reset_at reports when the caller may retry, which is the ban expiry.
      def build_ban_evaluation(rule, resolved_limit, resolved_period, count, ttl, ban_ttl)
        banned = ban_ttl >= 0
        window_remaining = ttl >= 0 ? ttl : resolved_period

        info = Result::Info.new(
          resolved_limit: resolved_limit, resolved_period: resolved_period,
          count: count,
          # A ban outlives its counter, so count reads 0 once the window has
          # gone. Nothing is remaining while the ban still blocks.
          remaining: banned ? 0 : remaining_of(resolved_limit, count),
          reset_at: Time.now.utc + (banned ? ban_ttl : window_remaining)
        )

        Result::Evaluation.new(rule: rule, exceeded: banned, info: info)
      end

      def build_evaluation(rule, resolved_limit, resolved_period, count, ttl)
        info = Result::Info.new(
          resolved_limit: resolved_limit, resolved_period: resolved_period,
          count: count,
          remaining: remaining_of(resolved_limit, count),
          reset_at: Time.now.utc + (ttl >= 0 ? ttl : resolved_period)
        )

        Result::Evaluation.new(rule: rule, exceeded: count > resolved_limit, info: info)
      end

      # RateLimit-Remaining must not exceed RateLimit-Limit, and a counter can
      # sit below zero if an older client credited it. A limit resolving to a
      # non-positive value means "deny all", so the ceiling floors at zero too.
      def remaining_of(resolved_limit, count)
        ceiling = [resolved_limit, 0].max
        (ceiling - count).clamp(0, ceiling)
      end

      # The braces are the cluster hash tag: a counter and its ban must share a
      # slot because BAN_SCRIPT touches both in one call. The rule name stays
      # inside it so one identifier's keys spread across nodes instead of piling
      # onto one. +suffix+ sits outside, so it cannot change the slot.
      def build_redis_key(rule, identifier, suffix = nil)
        key = "#{REDIS_KEY_PREFIX}:{#{@name}:#{rule.name}"
        rule.characteristics.each do |char|
          value = resolve_char_value(char, identifier)
          key << ":#{char}:#{encode_char_value(value)}"
        end
        key << "}"
        key << suffix if suffix
        key
      end

      def resolve_char_value(char, identifier)
        value = identifier[char]
        return MISSING_VALUE_SENTINEL if value.nil? || value.to_s.empty?

        value.to_s
      end

      # Resolve a limit/period value. Plain values pass through; callables are
      # invoked according to their arity:
      #
      # - Zero-arity callables call with no args (e.g. -> { ApplicationSetting.current.foo }).
      # - Callables with arity >= 1 receive +rule_context+, which may be nil
      #   if the caller didn't pass it. They must therefore handle nil -
      #   typically with `ctx&.[](:key) || default`.
      # - Variadic callables (negative arity, e.g. ->(*args) { ... }) take
      #   the zero-arg path. Opt into rule_context by writing the lambda
      #   with exactly one required parameter: ->(ctx) { ... }. This avoids
      #   the footgun where ->(*args) silently receives [rule_context] and
      #   the caller's overrides never take effect.
      # - Callables that respond to +call+ but not +arity+ (e.g. a class with
      #   `def call` and no explicit arity) take the zero-arg path, preserving
      #   the pre-rule_context behaviour for custom callable objects.
      #
      # This lets rules carry callables that depend on per-request context (e.g.
      # per-namespace settings) without rebuilding the Rule on every call or
      # smuggling state through globals.
      def resolve_value(val, rule_context = nil)
        return val unless val.respond_to?(:call)

        val.respond_to?(:arity) && val.arity >= 1 ? val.call(rule_context) : val.call
      end

      def encode_char_value(value)
        if value.length > CHAR_VALUE_MAX_LENGTH
          OpenSSL::Digest::SHA256.hexdigest(value)
        else
          value
        end
      end

      # Atomically increments the counter by `cost`, sets the TTL on first
      # write, and returns the window's remaining TTL, all in one Redis
      # operation via Lua. See INCR_SCRIPT for the script body.
      #
      # count is parsed as Float because INCRBYFLOAT returns a string-encoded
      # number; the Float is integer-valued when cost is 1, fractional
      # otherwise.
      def incr_with_ttl(redis_key, period, cost)
        @redis.with do |conn|
          raw_count, ttl = INCR_SCRIPT.eval(conn, keys: [redis_key], argv: [period, cost])
          [Float(raw_count), ttl]
        end
      end

      # Atomic ban check + increment + conditional ban write. See BAN_SCRIPT.
      # The returned ban TTL is negative when no ban is in force.
      def ban_incr_with_ttl(counter_key, ban_key, period, cost, limit, ban_for)
        @redis.with do |conn|
          raw_count, ttl, ban_ttl = BAN_SCRIPT.eval(
            conn, keys: [counter_key, ban_key], argv: [period, cost, limit, ban_for]
          )
          [Float(raw_count), Integer(ttl), Integer(ban_ttl)]
        end
      end

      # Pipelined read of both keys for #peek. No EXPIRE and no SET: peeking a
      # banned identifier must not extend either the window or the ban.
      def read_ban_with_ttl(counter_key, ban_key)
        @redis.with do |conn|
          raw_count, ttl, ban_ttl = conn.pipelined do |pipe|
            pipe.get(counter_key)
            pipe.ttl(counter_key)
            pipe.ttl(ban_key)
          end
          [raw_count.nil? ? 0.0 : Float(raw_count), Integer(ttl), Integer(ban_ttl)]
        end
      end

      # Pipelined GET + TTL. No EXPIRE: peek must not extend the window.
      # A missing key (GET => nil, TTL => -2) is reported as count=0; the
      # build_evaluation fallback then derives reset_at from the rule period
      # since there is no Redis-side window to read.
      #
      # Float parsing accepts both INCR-stored ("5") and INCRBYFLOAT-stored
      # ("5.7") values uniformly.
      def read_with_ttl(redis_key)
        @redis.with do |conn|
          raw_count, ttl = conn.pipelined do |pipe|
            pipe.get(redis_key)
            pipe.ttl(redis_key)
          end
          count = raw_count.nil? ? 0.0 : Float(raw_count)
          [count, ttl]
        end
      end

      # Atomic SADD + SCARD + conditional EXPIRE in one Redis operation via Lua.
      # See SADD_SCRIPT for the body. Mirrors incr_with_ttl's shape, including
      # the Float-typed count for uniformity with the INCR path.
      def sadd_with_ttl(redis_key, member, period)
        member_str = encode_char_value(member.to_s)
        @redis.with do |conn|
          raw_count, ttl = SADD_SCRIPT.eval(conn, keys: [redis_key], argv: [period, member_str])
          [Float(raw_count), ttl]
        end
      end

      # Pipelined SCARD + TTL. SCARD on a missing key returns 0, so no
      # explicit nil handling is needed (unlike GET in read_with_ttl).
      # SCARD is integer-valued; coerced to Float for type uniformity with
      # the INCR path so callers see a consistent count type.
      def scard_with_ttl(redis_key)
        @redis.with do |conn|
          scard, ttl = conn.pipelined do |pipe|
            pipe.scard(redis_key)
            pipe.ttl(redis_key)
          end
          [Float(scard), ttl]
        end
      end

      # rule is nil when the error was raised with no rule in flight - before the
      # loop reached one, or after it finished - so the field is logged as null
      # rather than omitted, the same way identifier is. A named rule is the rule
      # whose match or evaluation raised.
      # Never raises: a logging failure must not break fail-open.
      def log_error(error, identifier, rule = nil)
        @logger.warn(
          Labkit::Fields::LOG_MESSAGE => "rate_limit_error",
          name: @name,
          rule: rule&.name,
          Labkit::Fields::ERROR_TYPE => "rate_limit_error",
          Labkit::Fields::CLASS_NAME => error.class.to_s,
          Labkit::Fields::ERROR_MESSAGE => error.message,
          identifier: identifier&.to_h
        )
      rescue StandardError
        nil
      end

      def log_missing_count_distinct(rule, identifier)
        @logger.warn(
          message: "rate_limit_missing_count_distinct",
          name: @name,
          rule: rule.name,
          count_distinct: rule.count_distinct.to_s,
          identifier: identifier&.to_h
        )
      end

      def report_evaluation_metrics(evaluation)
        rule_labels = { rate_limiter: @name, rule: evaluation.rule.name }

        Metrics.safe_increment(
          :rule_evaluations_total,
          rule_labels.merge(action: evaluation.rule.action.to_s, result: evaluation_result(evaluation)),
          logger: @logger
        )
        Metrics.safe_set(:limit_gauge, rule_labels, evaluation.info.resolved_limit, logger: @logger)
        Metrics.safe_set(:period_gauge, rule_labels, evaluation.info.resolved_period, logger: @logger)
      end

      # An exceeded :log rule reports "log" rather than the "allow" the caller
      # sees, so shadow rules over their limit stay visible.
      # A ban is not a distinct action, so without this a blocking ban would be
      # indistinguishable from an ordinary block. On a ban_for rule exceeded?
      # means the ban is in force, whether this call wrote it or an earlier one
      # did, which is exactly what is worth counting separately.
      def evaluation_result(evaluation)
        return "allow" unless evaluation.exceeded?
        return "banned" if evaluation.rule.ban_for

        evaluation.rule.action == :limit ? "block" : "log"
      end

      def report_skipped_metrics(rule)
        Metrics.safe_increment(
          :rule_evaluations_total,
          { rate_limiter: @name, rule: rule.name, action: "skip", result: "skip" },
          logger: @logger
        )
      end

      def report_check_metrics(result)
        Metrics.safe_increment(
          :checks_total,
          {
            rate_limiter: @name,
            action: result.action.to_s,
            matched: result.matched?.to_s,
            error: (result.error? || result.degraded?).to_s
          },
          logger: @logger
        )
      end

      def report_peek_metrics(result)
        Metrics.safe_increment(
          :peeks_total,
          { rate_limiter: @name, error: (result.error? || result.degraded?).to_s },
          logger: @logger
        )
      end
    end
  end
end
