# frozen_string_literal: true

require 'strscan'

module SemverDialects
  module Maven
    ALPHA = -5
    BETA = -4
    MILESTONE = -3
    RC = -2
    SNAPSHOT = -1
    SP = 'sp'

    class Version < BaseVersion # rubocop:todo Style/Documentation
      attr_accessor :addition

      # Return an array similar to the one Maven generates when parsing versions.
      #
      #   $ java -jar ${MAVEN_HOME}/lib/maven-artifact-3.9.6.jar 1a1
      #   Display parameters as parsed by Maven (in canonical form and as a list of tokens) and comparison result:
      #    1. 1a1 -> 1-alpha-1; tokens: [1, [alpha, [1]]]
      #
      def to_a
        return tokens if addition.nil?

        tokens.clone.append(addition.to_a)
      end

      def to_s(as_addition = false) # rubocop:disable Style/OptionalBooleanParameter
        s = ''
        if tokens.any?
          s += '-' if as_addition
          s += tokens.map do |token|
            case token
            when String
              token
            when Integer
              case token
              when ALPHA
                'alpha'
              when BETA
                'beta'
              when MILESTONE
                'milestone'
              when RC
                'rc'
              when SNAPSHOT
                'snapshot'
              else
                token.to_s
              end
            end
          end.join('.')
        end
        s += addition.to_s(true) if addition
        s
      end

      private

      # Compare tokens as specified in https://maven.apache.org/pom.html#version-order-specification.
      # Negative integers are alpha, beta, milestone, rc, and snapshot qualifiers.
      # Special qualifier "sp" is right after GA and before any lexical or numeric token.
      # Strings should be converted to lower case before being compared by this method.
      # 1-a0 == 1-alpha < 1-0 == 1 == 1final == 1 ga < 1sp < 1-a < 1-1
      def compare_token_pair(a = 0, b = 0) # rubocop:todo Naming/MethodParameterName
        a ||= 0
        b ||= 0

        if a.is_a?(Integer) && b.is_a?(String)
          return a <= 0 ? -1 : 1
        end

        if a.is_a?(String) && b.is_a?(Integer)
          return b <= 0 ? 1 : -1
        end

        return -1 if a == SP && b.is_a?(String) && b != SP

        return 1 if b == SP && a.is_a?(String) && a != SP

        # Identifiers have both the same type.
        # This returns nil if the identifiers can't be compared.
        a <=> b
      end

      def empty_addition
        Version.new([])
      end
    end

    class VersionParser # rubocop:todo Style/Documentation
      def self.parse(input)
        new(input).parse
      end

      attr_reader :input

      def initialize(input)
        @input = input
      end

      def parse
        @scanner = StringScanner.new(input.downcase)
        @version = Version.new([])
        @result = @version
        parse_version(false)

        raise InvalidVersionError, input if @result.to_a.empty?

        result
      end

      private

      attr_reader :scanner, :version, :result

      # Parse a version and all its additions recursively.
      # It automatically creates a new partition for numbers
      # if number_begins_partition is true.
      def parse_version(number_begins_partition)
        # skip leading v if any
        scanner.skip(/v/)

        until scanner.eos?
          if (s = scanner.scan(/\d+/))
            if number_begins_partition
              parse_addition(s.to_i)
            else
              version.tokens << s.to_i
            end

          elsif (s = scanner.match?(/a\d+/))
            # aN is equivalent to alpha-N
            scanner.skip('a')
            parse_addition(ALPHA)

          elsif (s = scanner.match?(/b\d+/))
            # bN is equivalent to beta-N
            scanner.skip('b')
            parse_addition(BETA)

          elsif (s = scanner.match?(/m\d+/))
            # mN is equivalent to milestone-N
            scanner.skip('m')
            parse_addition(MILESTONE)

          elsif (s = scanner.scan(/(alpha|beta|milestone|rc|cr|sp|ga|final|release|snapshot)[a-z]+/))
            # process "alpha" and others as normal lexical tokens if they're followed by a letter
            parse_addition(s)

          elsif (s = scanner.scan('alpha'))
            # handle alphaN, alpha-X, alpha.X, or ending alpha
            parse_addition(ALPHA)

          elsif (s = scanner.scan('beta'))
            parse_addition(BETA)

          elsif (s = scanner.scan('milestone'))
            parse_addition(MILESTONE)

          elsif (s = scanner.scan(/(rc|cr)/))
            parse_addition(RC)

          elsif (s = scanner.scan('snapshot'))
            parse_addition(SNAPSHOT)

          elsif (s = scanner.scan(/ga|final|release/))
            parse_addition

          elsif (s = scanner.scan('sp'))
            parse_addition(SP)

          # The `+` character is allowed per the official Maven version parser,
          # so it's also parsed as an addition.
          #
          # See for more info https://gitlab.com/gitlab-org/gitlab/-/issues/466158
          elsif (s = scanner.scan(/[a-z_+]+/))
            parse_addition(s)

          elsif (s = scanner.scan('.'))
            number_begins_partition = false

          elsif (s = scanner.scan('-'))
            number_begins_partition = true

          else
            raise IncompleteScanError, scanner.rest
          end
        end
      end

      # Create an addition for the current version, make it the current version, and parse it.
      # Numbers start a new partition.
      def parse_addition(token = nil)
        version.addition = Version.new([token].compact)
        @version = version.addition

        scanner.skip(/-+/)
        parse_version(true)
      end
    end
  end
end
