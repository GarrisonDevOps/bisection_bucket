# frozen_string_literal: true

module Labkit
  module RateLimit
    KNOWN_ACTIONS = %i[limit log skip].freeze
    RULE_NAME_PATTERN = /\A[a-z0-9_]+\z/
    RULE_NAME_MAX_LENGTH = 64

    # Rule is a value object describing a single rate limit rule.
    # name            - stable identifier used in Redis keys and log entries
    # match           - hash of identifier key/value pairs that must all match for
    #                   the rule to apply; empty hash matches any identifier
    # limit           - request threshold, at least 1; may be a callable (resolved per check)
    # period          - window in seconds, at least 1; may be a callable (resolved per check)
    # action          - :limit (enforce; the result blocks when the rule is over
    #                   its limit, which also terminates evaluation), :log (count
    #                   and log only, never blocks and never terminates),
    #                   or :skip (bypass: permit and terminate evaluation on
    #                   match without counting; performs no Redis operation, so
    #                   limit, period, characteristics, and count_distinct are
    #                   inert)
    # ban_for         - optional ban duration in seconds. On crossing the limit
    #                   the rule writes a separate ban key that outlives the
    #                   counter window, and stops counting while it holds.
    #                   +action+ still decides who is blocked: :limit enforces
    #                   the ban, :log records what it would have done. Rejected
    #                   on :skip. May be a callable, resolved per check.
    # characteristics - identifier keys used to build the compound Redis counter key
    # count_distinct  - optional Symbol naming an identifier key. When set, the rule
    #                   counts the number of distinct values seen for that key within
    #                   the (characteristics-bucketed) period, backed by a Redis SET.
    #                   When nil (default), the rule counts the number of calls,
    #                   backed by INCR. The named key must not overlap +characteristics+.
    #
    # +name+ must be a lowercase alphanumeric-and-underscore string of at most 64
    # characters. It is used as the middle segment of every Redis counter key for
    # this rule, so changing a rule's name mid-window abandons its in-flight counters.
    Rule = Data.define(:name, :match, :limit, :period, :action, :characteristics, :count_distinct, :ban_for) do
      # ban_for changes the accounting; action still decides who gets blocked.
      # A :skip rule counts nothing, so it has no limit to cross and no ban to
      # write.
      def self.normalize_ban_for(value, action_sym, count_distinct_sym)
        return nil if value.nil?

        raise ArgumentError, "ban_for is not valid on a :skip rule" if action_sym == :skip

        # The ban path counts with INCRBYFLOAT, so a SET-backed rule would
        # silently count calls instead of distinct values.
        raise ArgumentError, "ban_for cannot be combined with count_distinct #{count_distinct_sym.inspect}" if count_distinct_sym

        return value if value.respond_to?(:call)
        # Whole seconds: the ban is written with SET EX, and anything under a
        # second truncates to 0, which Redis rejects.
        return value if value.is_a?(Numeric) && value >= 1

        raise ArgumentError, "ban_for must be a Numeric of at least 1 second or a callable, got #{value.inspect}"
      end

      # A static limit under 1 blocks every request, and a period under a second
      # reaches EXPIRE as 0, deleting the counter on every write. A :skip rule
      # counts nothing, and a callable may still resolve to 0 to mean "deny all".
      def self.normalize_numeric(field, value, action_sym)
        return value if action_sym == :skip || value.respond_to?(:call)
        return value if value.is_a?(Numeric) && value >= 1

        raise ArgumentError, "#{field} must be a Numeric of at least 1 or a callable, got #{value.inspect}"
      end

      def self.normalize_count_distinct(value, characteristics_arr)
        sym =
          case value
          when nil    then nil
          when Symbol then value
          when String then value.to_sym
          else
            raise ArgumentError, "count_distinct must be a Symbol, String, or nil, got #{value.class}"
          end

        raise ArgumentError, "count_distinct #{sym.inspect} must not overlap characteristics #{characteristics_arr.inspect}" if sym && characteristics_arr.include?(sym)

        sym
      end

      def initialize(
        name:, limit:, period:, characteristics:,
        match: {}, action: :limit, count_distinct: nil, ban_for: nil
      )
        raise ArgumentError, "name must be a String or Symbol, got #{name.class}" unless name.is_a?(String) || name.is_a?(Symbol)

        name_str = name.to_s
        raise ArgumentError, "name must not be empty" if name_str.empty?

        action_sym = action.to_sym
        raise ArgumentError, "Invalid action: #{action.inspect}. Must be one of: #{KNOWN_ACTIONS.inspect}" unless KNOWN_ACTIONS.include?(action_sym)

        if Labkit.dev_or_test?
          raise ArgumentError, "Invalid rule name: #{name.inspect}. Must match /\\A[a-z0-9_]+\\z/" unless RULE_NAME_PATTERN.match?(name_str)
          raise ArgumentError, "Rule name too long: #{name.inspect}. Maximum 64 characters" if name_str.length > RULE_NAME_MAX_LENGTH
        end

        characteristics_arr = Array(characteristics).map(&:to_sym).freeze
        count_distinct_sym = self.class.normalize_count_distinct(count_distinct, characteristics_arr)

        super(
          name: name_str.freeze,
          match: match.transform_keys(&:to_sym).transform_values { |v| Matcher.build(v) }.freeze,
          limit: self.class.normalize_numeric(:limit, limit, action_sym),
          period: self.class.normalize_numeric(:period, period, action_sym),
          action: action_sym,
          characteristics: characteristics_arr,
          count_distinct: count_distinct_sym,
          ban_for: self.class.normalize_ban_for(ban_for, action_sym, count_distinct_sym)
        )
      end
    end
  end
end
