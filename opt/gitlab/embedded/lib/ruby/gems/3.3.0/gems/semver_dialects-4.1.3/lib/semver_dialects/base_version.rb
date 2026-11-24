# frozen_string_literal: true

# Class that describes a version that can be compared to another version in a generic way.
#
# A version is made of +tokens+ and an optional +addition+.
# Tokens and additions must be comparable using the spaceship operator.
# An addition behaves like a version and must respond to +tokens+.
#
# Tokens are used to represent the dot separated list of segments
# like 1.2.3 (semantic version) or alpha.1 (pre-release tag).
#
# Version 1.2.3-alpha.1-2024.03.25 is made of 3 +Version+ objects
# whose tokens are represented as 1.2.3, alpha.1, 2024.03.25.
# Version alpha.1 is the addition of version 1.2.3,
# and version 2024.03.25 is the addition of version alpha.1.
#
# This class can support of the comparison logic of many syntaxes
# by implementing specific token classes.
#
module SemverDialects
  class BaseVersion # rubocop:todo Style/Documentation
    include Comparable

    attr_reader :tokens, :addition

    def initialize(tokens, addition: nil)
      @tokens = tokens
      @addition = addition
    end

    def to_s
      main = tokens.join('.')
      main += "-#{addition}" if addition
      main
    end

    def <=>(other)
      cmp = compare_tokens(tokens, other.tokens)
      return cmp unless cmp.zero?

      compare_additions(addition, other.addition)
    end

    # Returns true if the version tokens are equivalent to zero
    # and the addition is also equivalent to zero.
    def is_zero? # rubocop:todo Naming/PredicateName
      return false if compare_tokens(tokens, [0]) != 0

      return true if addition.nil?

      addition.is_zero?
    end

    private

    def compare_tokens(a, b) # rubocop:disable Naming/MethodParameterName
      max_idx = [a.size, b.size].max - 1
      (0..max_idx).each do |idx|
        cmp = compare_token_pair(a[idx], b[idx])
        return cmp unless cmp.zero?
      end
      0
    end

    def compare_token_pair(a, b) # rubocop:disable Naming/MethodParameterName
      (a || 0) <=> (b || 0)
    end

    def compare_additions(a, b) # rubocop:disable Naming/MethodParameterName
      return 0 if a.nil? && b.nil?

      (a || empty_addition).<=>(b || empty_addition)
    end

    def empty_addition
      self.class.new([])
    end
  end
end
