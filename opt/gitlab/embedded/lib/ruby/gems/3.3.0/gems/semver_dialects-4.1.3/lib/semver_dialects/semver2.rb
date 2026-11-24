# frozen_string_literal: true

require 'strscan'

module SemverDialects
  module Semver2
    # Represents a token that matches any major, minor, or patch number.
    ANY_NUMBER = 'x'

    class Version < BaseVersion # rubocop:todo Style/Documentation
      def initialize(tokens, prerelease_tag: nil) # rubocop:todo Lint/MissingSuper
        @tokens = tokens
        @addition = prerelease_tag
      end

      def <=>(other)
        if (idx = tokens.index(ANY_NUMBER))
          a = tokens[0..(idx - 1)]
          b = other.tokens[0..(idx - 1)]
          return compare_tokens(a, b)
        end

        if (idx = other.tokens.index(ANY_NUMBER))
          a = tokens[0..(idx - 1)]
          b = other.tokens[0..(idx - 1)]
          return compare_tokens(a, b)
        end

        super
      end

      private

      # Compares pre-release tags as specified in https://semver.org/#spec-item-9.
      def compare_additions(a, b) # rubocop:disable Naming/MethodParameterName
        #  Pre-release versions have a lower precedence than the associated normal version.
        return -1 if !a.nil? && b.nil? # only self is a pre-release
        return 1 if a.nil? && !b.nil? # only other is a pre-release

        a <=> b
      end
    end

    class PrereleaseTag < BaseVersion # rubocop:todo Style/Documentation
      def initialize(tokens) # rubocop:todo Lint/MissingSuper
        @tokens = tokens
      end

      # Returns true if the prerelease tag is empty.
      # In Semver 2 1.2.3-0 is NOT equivalent to 1.2.3.
      def is_zero? # rubocop:todo Naming/PredicateName
        tokens.empty?
      end

      private

      # Compares pre-release identifiers as specified in https://semver.org/#spec-item-11.
      def compare_token_pair(a, b) # rubocop:disable Naming/MethodParameterName
        case a
        when Integer
          case b
          when String
            # Numeric identifiers always have lower precedence than non-numeric identifiers.
            return -1
          when nil
            # A larger set of pre-release fields has a higher precedence than a smaller set,
            # if all of the preceding identifiers are equal.
            return 1
          end
        when String
          case b
          when Integer
            # Numeric identifiers always have lower precedence than non-numeric identifiers.
            return 1
          when nil
            # A larger set of pre-release fields has a higher precedence than a smaller set,
            # if all of the preceding identifiers are equal.
            return 1
          end
        when nil
          case b
          when Integer
            # A larger set of pre-release fields has a higher precedence than a smaller set,
            # if all of the preceding identifiers are equal.
            return -1
          when String
            # A larger set of pre-release fields has a higher precedence than a smaller set,
            # if all of the preceding identifiers are equal.
            return -1
          end
        end
        # Identifiers have both the same type (numeric or non-numeric).
        # This returns nil if the identifiers can't be compared.
        a <=> b
      end
    end

    class VersionParser # rubocop:todo Style/Documentation
      def self.parse(input)
        new(input).parse
      end

      attr_reader :input

      def initialize(input)
        @input = input
        @scanner = StringScanner.new(input)
      end

      def parse
        tokens = []
        prerelease_tag = nil

        # skip ignore leading v if any
        scanner.skip('v')

        until scanner.eos?
          if (s = scanner.scan(/\d+/))
            tokens << s.to_i
          elsif (s = scanner.scan(/\.x\z/i))
            tokens << ANY_NUMBER
          elsif (s = scanner.scan('.'))
            # continue
          elsif (s = scanner.scan('-'))
            prerelease_tag = parse_prerelease_tag
          elsif (s = scanner.scan(/\+.*/))
            # continue
          else
            raise IncompleteScanError, scanner.rest
          end
        end

        Version.new(tokens, prerelease_tag:)
      end

      private

      attr_reader :scanner

      def parse_prerelease_tag
        tokens = []
        at_build_tag = false

        until scanner.eos? || at_build_tag
          if (s = scanner.scan(/\d+(?![a-zA-Z-])/))
            tokens << s.to_i
          elsif (s = scanner.scan(/[0-9a-zA-Z-]+/))
            tokens << s
          elsif (s = scanner.scan('.'))
            # continue
          elsif (s = scanner.scan('+'))
            scanner.unscan
            at_build_tag = true
          else
            raise IncompleteScanError, scanner.rest
          end
        end

        PrereleaseTag.new(tokens)
      end
    end
  end
end
