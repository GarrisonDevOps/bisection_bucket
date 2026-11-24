# frozen_string_literal: true

require "set"

module Labkit
  module RateLimit
    # Matcher is the internal representation of a single key/value predicate in
    # a Rule#match hash. Rule.new normalizes every match value through
    # Matcher.build; the Evaluator calls Matcher#match? per identifier value.
    #
    # Accepted input shapes (everything else raises ArgumentError):
    #   - any plain value (String, Symbol, Integer, ...) -> :eq matcher
    #   - a Regexp instance                              -> :re matcher (Ruby convenience)
    #   - { eq: <value> }                                -> :eq matcher (canonical, YAML-compatible)
    #   - { ne: <value> }                                -> :ne matcher (complement of :eq)
    #   - { re: <String|Regexp> }                        -> :re matcher (canonical, YAML-compatible)
    #   - { nre: <String|Regexp> }                       -> :nre matcher (complement of :re)
    #   - { oneOf: <Array> }                             -> :oneOf matcher (set membership, YAML-compatible)
    #   - { noneOf: <Array> }                            -> :noneOf matcher (complement of :oneOf)
    #   - [ <matcher>, <matcher>, ... ]                  -> :all matcher (every entry must match)
    #
    # An Array means AND, so several predicates can apply to one identifier key.
    # Its entries must be matcher Hashes or bare Regexps, the two shapes that
    # already mean "a matcher" on their own. An Array of plain values is
    # rejected, so a value that was meant as a single matcher but arrived as a
    # list fails loudly instead of silently becoming a membership test. An Array
    # holds matchers rather than other Arrays, so a match value nests at most
    # MAX_NESTING_DEPTH deep; see too_deeply_nested?.
    #
    # :oneOf and :noneOf membership is Set#include? (eql?/hash equality), not
    # :eq's ==, so cross-type numerics differ (1 == 1.0, but {oneOf: [1]} does
    # not match 1.0).
    #
    # Hash-key naming follows the metrics-catalog selector pattern. Glob,
    # prefix, and other matcher kinds are intentionally out of scope here; see
    # gitlab-com/gl-infra/production-engineering#28853 for that follow-up.
    #
    # The :re and :nre matchers coerce the identifier value via #to_s before
    # applying the regex, so callers can match non-String identifier values such
    # as Integer status codes (e.g. {status: { re: "^5" }} against status: 503).
    #
    # Each negation matcher is the plain complement of its positive form, with
    # no special case for a missing key. Evaluator passes identifier[key], so an
    # absent key arrives as nil, and the complement is therefore usually true
    # for one: a request with no path is not a request to an excluded path. A
    # rule that should apply only when the key is present says so, by adding a
    # presence matcher alongside the exclusions:
    #
    #   path: [/./, { nre: '\A/api/' }]
    class Matcher < Data.define(:type, :value)
      KNOWN_HASH_KEYS = %i[eq ne re nre oneOf noneOf].freeze
      ERROR_INSPECT_LIMIT = 80
      # No Hash or Array may sit this many levels below the match value, which
      # is level 0. The deepest valid shape is an Array (0) holding a matcher
      # Hash (1) whose :oneOf list (2) holds plain values; see
      # too_deeply_nested?.
      MAX_NESTING_DEPTH = 3

      # Wall-clock budget for a single #match? call. Without it a match is
      # bounded only by whatever global the host sets (40s in GitLab Rails,
      # unbounded elsewhere), and a timeout reaches Evaluator's fail-open
      # rescue, so the request goes unlimited.
      #
      # 50ms is a safety net against catastrophic backtracking, not a
      # performance bound: real matches are far cheaper (median 0.087ms, worst
      # 1.484ms across 6935 paths that timed out in production at 5ms). Those
      # timeouts were wall-clock stalls, since Ruby counts real time and GC
      # pauses on GitLab's git fleet have a p50 of ~72ms. Under 4x CPU
      # oversubscription 50ms still fires on 0.16% of those matches, 5ms 1.33%.
      #
      # This timeout is the only bound on a pattern. There is no cap on regex
      # source length: rules are written by operators rather than end users, and
      # a cap that applied to {re: "..."} but not to a bare Regexp bounded
      # nothing in practice, since callers pass Regexp constants.
      MATCH_TIMEOUT_SECONDS = 0.05

      def self.build(input)
        raise ArgumentError, nesting_error(input) if too_deeply_nested?(input)

        case input
        when Regexp
          new(type: :re, value: with_match_timeout(:re, input))
        when Hash
          from_hash(input)
        when Array
          compose(input)
        else
          new(type: :eq, value: input)
        end
      end

      def self.from_hash(input)
        raise ArgumentError, invalid_shape_error(input) if input.size != 1

        type, source = input.first

        # Identifier rejects keys the same way. Without this, a key such as an
        # Integer or nil leaves NoMethodError for the caller instead of the
        # ArgumentError every other bad shape raises.
        unless type.respond_to?(:to_sym)
          raise ArgumentError,
            "rate-limit match value type key #{truncate_for_error(type)} must be a String or Symbol"
        end

        type_sym = type.to_sym

        unless KNOWN_HASH_KEYS.include?(type_sym)
          raise ArgumentError,
            "rate-limit match value has unknown type key #{truncate_for_error(type)}; accepted: #{KNOWN_HASH_KEYS.inspect}"
        end

        compile(type_sym, source)
      end
      private_class_method :from_hash

      def self.compile(type_sym, source)
        case type_sym
        when :eq, :ne
          new(type: type_sym, value: source)
        when :oneOf, :noneOf
          unless source.is_a?(Array)
            raise ArgumentError,
              "rate-limit match value {#{type_sym}: ...} must be an Array, got #{truncate_for_error(source)}"
          end

          # {oneOf: []} matches nothing, so the rule never applies and no harm
          # follows. Its complement matches everything, which is an exclusion
          # that excludes nothing: rejected for the same reason an empty Array
          # of matchers is.
          if type_sym == :noneOf && source.empty?
            raise ArgumentError,
              "rate-limit match value {noneOf: []} must not be empty, it matches everything"
          end

          new(type: type_sym, value: Set.new(source).freeze)
        when :re, :nre
          new(type: type_sym, value: with_match_timeout(type_sym, source))
        end
      end
      private_class_method :compile

      # Builds the :all matcher behind the Array form. Entries go back through
      # .build, which is what keeps a nested regex bounded by the match timeout.
      def self.compose(input)
        raise ArgumentError, "rate-limit match value [] must not be empty" if input.empty?

        unless input.all? { |entry| entry.is_a?(Hash) || entry.is_a?(Regexp) }
          raise ArgumentError,
            "rate-limit match value Array entries must each be a matcher Hash or Regexp, " \
              "got #{truncate_for_error(input)}"
        end

        new(type: :all, value: input.map { |entry| build(entry) }.freeze)
      end
      private_class_method :compose

      # Compiles +source+ (a String pattern or an existing Regexp) into a
      # Regexp bounded by MATCH_TIMEOUT_SECONDS.
      #
      # The timeout is set per-Regexp rather than via the global
      # +Regexp.timeout=+: labkit is a library, and a global would silently
      # change regex behaviour throughout the host application, including
      # code unrelated to rate limiting.
      #
      # A Regexp that already carries its own timeout is returned untouched -
      # an explicit choice by the rule author wins over our default.
      #
      # Recompiling an existing Regexp preserves its source and options
      # (including the fixed-encoding flags) and therefore +#==+; only object
      # identity changes.
      def self.with_match_timeout(key, source)
        return source if source.is_a?(Regexp) && source.timeout

        if source.is_a?(Regexp)
          Regexp.new(source.source, source.options, timeout: MATCH_TIMEOUT_SECONDS)
        else
          Regexp.new(source, timeout: MATCH_TIMEOUT_SECONDS)
        end
      rescue RegexpError, TypeError => e
        raise ArgumentError,
          "rate-limit match value {#{key}: #{truncate_for_error(source)}} failed to compile: #{e.message}"
      end

      private_class_method :with_match_timeout

      def self.invalid_shape_error(input)
        # No key list here: this fires on the shape, and from_hash names the
        # accepted keys when the shape is right but the key is not. Keeping the
        # fixed part short is also what lets truncate_for_error bound the whole
        # message.
        "rate-limit match value must be a single-key Hash, or an Array of matchers, " \
          "got #{truncate_for_error(input)}"
      end
      private_class_method :invalid_shape_error

      def self.truncate_for_error(value)
        s = value.inspect
        s.length > ERROR_INSPECT_LIMIT ? "#{s[0, ERROR_INSPECT_LIMIT]}...(truncated)" : s
      end
      private_class_method :truncate_for_error

      def self.nesting_error(input)
        # Does not inspect the input: it is too deep to render, which is the
        # reason this fires. The class is the only hint available cheaply, and
        # the nesting may be in a key or a value.
        "rate-limit match value nests deeper than #{MAX_NESTING_DEPTH} levels (#{input.class})"
      end
      private_class_method :nesting_error

      # A valid match value nests three deep at most: an Array of matcher
      # Hashes whose :oneOf value is an Array of plain values. Anything past
      # MAX_NESTING_DEPTH is rejected rather than built.
      #
      # The check is iterative because the alternative is finding out through
      # #inspect, which recurses once per level while rendering an error
      # message. Rules are built at boot and SystemStackError is not a
      # StandardError, so that would take the process down rather than reject
      # one rule, and rescuing it is not an option either: the VM aborts on a
      # second overflow in the same process.
      def self.too_deeply_nested?(input)
        # A flat stack of node, depth pairs, so a visit allocates no Array. The
        # pops must mirror the pushes: depth comes off first, then its node.
        stack = [input, 0]

        until stack.empty?
          depth = stack.pop
          node = stack.pop
          next unless node.is_a?(Hash) || node.is_a?(Array)
          return true if depth >= MAX_NESTING_DEPTH

          # Keys as well as values: #inspect renders both, so a deeply nested
          # key overflows the same way a deeply nested value does.
          if node.is_a?(Hash)
            node.each { |key, value| stack.push(key, depth + 1, value, depth + 1) }
          else
            node.each { |child| stack.push(child, depth + 1) }
          end
        end

        false
      end
      private_class_method :too_deeply_nested?

      def match?(identifier_value)
        case type
        when :eq
          value == identifier_value
        when :ne
          value != identifier_value
        when :oneOf
          value.include?(identifier_value)
        when :noneOf
          # exclude? is ActiveSupport, and nothing in rate_limit requires it.
          !value.include?(identifier_value) # rubocop:disable Rails/NegateInclude
        when :re
          value.match?(identifier_value.to_s)
        when :nre
          !value.match?(identifier_value.to_s)
        when :all
          value.all? { |matcher| matcher.match?(identifier_value) }
        else
          raise ArgumentError, "unknown matcher type: #{type.inspect}"
        end
      end
    end
  end
end
