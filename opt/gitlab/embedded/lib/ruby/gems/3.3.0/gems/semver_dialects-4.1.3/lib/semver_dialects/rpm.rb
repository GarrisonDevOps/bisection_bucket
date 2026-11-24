# frozen_string_literal: true

require 'strscan'

module SemverDialects
  module Rpm
    module TokenPairComparison # rubocop:todo Style/Documentation
      # Token can be either alphabets, integers or tilde.
      # Caret is currently not supported. More details here https://gitlab.com/gitlab-org/gitlab/-/issues/428941#note_1882343489
      # Precedence: numeric token > string token > no token > tilda (~)
      def compare_token_pair(a, b) # rubocop:todo Naming/MethodParameterName
        return 1 if a != '~' && b == '~'
        return -1 if a == '~' && b != '~'

        return 1 if !a.nil? && b.nil?
        return -1 if a.nil? && !b.nil?

        return 1 if a.is_a?(Integer) && b.is_a?(String)
        return -1 if a.is_a?(String) && b.is_a?(Integer)

        # Remaining scenario are tokens of the same type ie Integer or String. Use <=> to compare
        a <=> b
      end
    end

    # This implementation references `go-rpm-version` https://github.com/knqyf263/go-rpm-version
    # Which is based on the official `rpmvercmp`
    # https://github.com/rpm-software-management/rpm/blob/master/rpmio/rpmvercmp.c implementation
    # rpm versioning schema can be found here https://github.com/rpm-software-management/rpm/blob/master/docs/manual/dependencies.md#versioning
    # Details on how the caret and tilde symbols are handled can be found here https://docs.fedoraproject.org/en-US/packaging-guidelines/Versioning/#_handling_non_sorting_versions_with_tilde_dot_and_caret
    class Version < BaseVersion
      include TokenPairComparison

      attr_reader :tokens, :addition, :epoch

      def initialize(tokens, epoch: nil, release_tag: nil) # rubocop:todo Lint/MissingSuper
        @tokens = tokens
        @addition = release_tag
        @epoch = epoch
      end

      def <=>(other)
        # Compare epoch first
        epoch_cmp = compare_epochs(epoch, other.epoch)
        return epoch_cmp unless epoch_cmp.zero?

        # Then compare version
        cmp = compare_tokens(tokens, other.tokens)
        return cmp unless cmp.zero?

        # And finally compare release tags
        compare_additions(addition, other.addition)
      end

      # Note that to_s does not accurately recreate the version string.
      # More details here https://gitlab.com/gitlab-org/gitlab/-/issues/428941#note_1882343489
      def to_s
        main = if !epoch.nil?
                 "#{epoch}:" + tokens.join('.')
               else
                 tokens.join('.')
               end
        main += "-#{addition.tokens.join('.')}" unless addition.nil?

        # Remove . around ~
        main.gsub(/\.~\./, '~')
      end

      private

      def compare_epochs(a, b) # rubocop:todo Naming/MethodParameterName
        (a || 0) <=> (b || 0)
      end
    end

    class ReleaseTag < BaseVersion # rubocop:todo Style/Documentation
      include TokenPairComparison

      def initialize(tokens) # rubocop:todo Lint/MissingSuper
        @tokens = tokens
      end
    end

    class VersionParser # rubocop:todo Style/Documentation
      DASH = /-/
      ALPHABET = /([a-zA-Z]+)/
      TILDE = /~/
      DIGIT = /([0-9]+)/
      COLON = /:/
      NON_ALPHANUMERIC_DASH_TILDE_AND_WHITESPACE = /[^a-zA-Z0-9~\s]+/
      WHITE_SPACE = /\s/

      def self.parse(input)
        new(input).parse
      end

      def initialize(input)
        @input = input
        @scanner = StringScanner.new(input)
      end

      # parse splits the input string into epoch, version and release tag Eg: <epoch>:<version>-<release_tag>
      # The version and release tag are split at the first `-` character if present
      # With the segment before the first `-` being version while the other being release tag
      # Subsequent `-` are disregarded
      def parse
        epoch = nil
        if (s = scanner.scan(/\d+:/))
          epoch = s[..-2].to_i
        end

        # parse tokens until we reach the release tag, if any
        tokens = parse_tokens(false)

        # parse release tag
        release_tag = nil
        release_tag = ReleaseTag.new(parse_tokens(true)) if scanner.rest?

        raise IncompleteScanError, scanner.rest if scanner.rest?

        Version.new(tokens, epoch:, release_tag:)
      end

      private

      attr_reader :scanner, :input

      def parse_tokens(stop_at_release_tag)
        tokens = []

        until scanner.eos?
          case
          when (s = scanner.scan(DASH))
            return tokens unless stop_at_release_tag
            # If release tag has been encountered, ignore subsequent dashes
          when (s = scanner.scan(ALPHABET))
            tokens << s
          when (s = scanner.scan(TILDE))
            tokens << s
          when (s = scanner.scan(DIGIT))
            tokens << s.to_i
          when (s = scanner.scan(WHITE_SPACE))
            # Whitespace is not permitted
            # https://github.com/rpm-software-management/rpm/blob/4d1b7401415003720ea9bef7bda248f7de4fa025/docs/manual/dependencies.md#versioning
            raise SemverDialects::InvalidVersionError, input
          when (s = scanner.scan(NON_ALPHANUMERIC_DASH_TILDE_AND_WHITESPACE))
            # Non-ascii characters are considered equal
            # so they are ignored when parsing versions
            # https://github.com/rpm-software-management/rpm/blob/rpm-4.19.1.1-release/tests/rpmvercmp.at#L143
          else
            raise SemverDialects::IncompleteScanError, scanner.rest
          end
        end
        tokens
      end
    end
  end
end
