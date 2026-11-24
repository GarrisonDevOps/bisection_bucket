# frozen_string_literal: true

require 'strscan'

module SemverDialects
  module Apk
    # This implementation references the version.c apk-tools implementation
    # https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/6052bfef57a81d82451b4cad86f78a2d01959767/src/version.c
    # apk version spec can be found here https://wiki.alpinelinux.org/wiki/APKBUILD_Reference#pkgver
    class Version < BaseVersion
      PRE_RELEASE_ORDER = { 'alpha' => 0, 'beta' => 1, 'pre' => 2, 'rc' => 3 }.freeze
      POST_RELEASE_ORDER = { 'cvs' => 0, 'svn' => 1, 'git' => 2, 'hg' => 3, 'p' => 4 }.freeze

      attr_reader :tokens, :pre_release, :post_release, :revision

      def initialize(tokens, pre_release: [], post_release: [], revision: []) # rubocop:todo Lint/MissingSuper
        @tokens = tokens
        @pre_release = pre_release
        @post_release = post_release
        @revision = revision
      end

      def <=>(other)
        cmp = compare_tokens(tokens, other.tokens)
        return cmp unless cmp.zero?

        cmp = compare_pre_release(pre_release, other.pre_release)
        return cmp unless cmp.zero?

        cmp = compare_post_release(post_release, other.post_release)
        return cmp unless cmp.zero?

        compare_revisions(revision, other.revision)
      end

      # Note that to_s does not accurately recreate the version string
      # if alphabets are present in the version segment.
      # For instance 1.2.a or 1.2a would both be returned as 1.2.a with to_s
      # More details in https://gitlab.com/gitlab-org/ruby/gems/semver_dialects/-/merge_requests/97#note_1989192447
      def to_s
        @to_s ||= begin
          main = tokens.join('.')
          main += "_#{pre_release.join('')}" unless pre_release.empty?
          main += "_#{post_release.join('')}" unless post_release.empty?
          main += "-#{revision.join('')}" unless revision.empty?
          main
        end
      end

      private

      # Token can be either integer or string
      # Precedence: numeric token > string token > no token
      def compare_token_pair(a, b) # rubocop:todo Naming/MethodParameterName
        return 1 if !a.nil? && b.nil?
        return -1 if a.nil? && !b.nil?

        return 1 if a.is_a?(Integer) && b.is_a?(String)
        return -1 if a.is_a?(String) && b.is_a?(Integer)

        # Remaining scenario are tokens of the same type ie Integer or String. Use <=> to compare
        a <=> b
      end

      # Precedence: post-release > no release > pre-release
      # https://wiki.alpinelinux.org/wiki/APKBUILD_Reference#pkgver
      def compare_pre_release(a, b) # rubocop:todo Naming/MethodParameterName
        return 0 if a.empty? && b.empty?
        return -1 if !a.empty? && b.empty?
        return 1 if a.empty? && !b.empty?

        compare_suffix(a, b, PRE_RELEASE_ORDER)
      end

      # Precedence: post-release > no release > pre-release
      # https://wiki.alpinelinux.org/wiki/APKBUILD_Reference#pkgver
      def compare_post_release(a, b) # rubocop:todo Naming/MethodParameterName
        return 0 if a.empty? && b.empty?
        return 1 if !a.empty? && b.empty?
        return -1 if a.empty? && !b.empty?

        compare_suffix(a, b, POST_RELEASE_ORDER)
      end

      # Pre-release precedence: alpha < beta < pre < rc
      # Post-release precedence: cvs < svn < git < hg < p
      # Precedence for releases with number eg alpha1:
      # release without number < release with number
      def compare_suffix(a, b, order) # rubocop:todo Naming/MethodParameterName
        a_suffix = order[a[0]]
        b_suffix = order[b[0]]

        return 1 if a_suffix > b_suffix
        return -1 if a_suffix < b_suffix

        a_value = a[1]
        b_value = b[1]

        return 1 if !a_value.nil? && b_value.nil?
        return -1 if a_value.nil? && !b_value.nil?

        (a_value || 0) <=> (b_value || 0)
      end

      def compare_revisions(a, b) # rubocop:todo Naming/MethodParameterName
        return 0 if a.empty? && b.empty?
        return 1 if !a.empty? && b.empty?
        return -1 if a.empty? && !b.empty?

        a_value = a[1]
        b_value = b[1]

        return 1 if !a_value.nil? && b_value.nil?
        return -1 if a_value.nil? && !b_value.nil?

        (a_value || 0) <=> (b_value || 0)
      end
    end

    class VersionParser # rubocop:todo Style/Documentation
      DASH = /-/
      ALPHABETS = /([a-zA-Z]+)/
      DIGITS = /([0-9]+)/
      DIGIT = /[0-9]/
      DOT = '.'
      UNDERSCORE = '_'
      PRE_RELEASE_SUFFIXES = %w[alpha beta pre rc].freeze
      POST_RELEASE_SUFFIXES = %w[cvs svn git hg p].freeze
      WHITE_SPACE = /\s/

      def self.parse(input)
        new(input).parse
      end

      attr_reader :scanner, :input

      def initialize(input)
        @input = input
        @pre_release = []
        @post_release = []
        @revision = []
        @scanner = StringScanner.new(input)
      end

      # Parse splits the raw version string into:
      # version, pre_release, post_release and revision
      # Format: <version>_<release>-<revision>
      # Note that version segment can contain alphabets
      # Release is always preceded with `_`
      # Revision is always preceded with `-`
      def parse
        tokens = parse_tokens

        Version.new(tokens, pre_release: @pre_release, post_release: @post_release, revision: @revision)
      end

      private

      def parse_tokens
        tokens = []

        until scanner.eos?
          case
          when (s = scanner.scan(ALPHABETS))
            tokens << s
          when (s = scanner.scan(DIGITS))
            # TODO: add support to parse numbers with leading zero https://gitlab.com/gitlab-org/gitlab/-/issues/471509
            raise SemverDialects::UnsupportedVersionError, input if s.start_with?('0') && s.length > 1

            tokens << s.to_i
          when (s = scanner.scan(UNDERSCORE))
            parse_release
            # Continue parsing if there's remaining tokens since revision which comes after release is optional
            return tokens if scanner.eos?
          when (s = scanner.scan(DASH))
            parse_revision
            return tokens
          when (s = scanner.scan(WHITE_SPACE))
            # Raise error if there's whitespace
            raise SemverDialects::InvalidVersionError, input
          when (s = scanner.scan(DOT))
            # Skip parsing dot
          else
            raise SemverDialects::IncompleteScanError, scanner.rest
          end
        end
        tokens
      end

      # PRE_RELEASE_SUFFIXES: alpha, beta, pre, rc
      # POST_RELEASE_SUFFIXES: cvs, svn, git, hg, p
      # No other suffixes are allowed
      # Release can be either `<suffix>` or `<suffix><number>` with the number being optional
      def parse_release
        # TODO: Add support to parse version with multiple releases
        raise SemverDialects::UnsupportedVersionError, input if !@pre_release.empty? || !@post_release.empty?

        suffix_type = nil
        until scanner.eos?
          case
          when (s = scanner.scan(ALPHABETS))
            if PRE_RELEASE_SUFFIXES.include?(s)
              suffix_type = :pre
              @pre_release << s
            elsif POST_RELEASE_SUFFIXES.include?(s)
              suffix_type = :post
              @post_release << s
            else
              raise SemverDialects::InvalidVersionError, input
            end
            return unless scanner.peek(1) =~ DIGIT
          when (s = scanner.scan(DIGITS))
            if suffix_type == :pre
              @pre_release << s.to_i
              return
            elsif suffix_type == :post
              @post_release << s.to_i
              return
            end
          else
            raise SemverDialects::InvalidVersionError, input
          end
        end
      end

      # Revision can be either `r` or `r<number>` with the number being optional
      def parse_revision
        until scanner.eos?
          case
          when (s = scanner.scan(ALPHABETS))
            raise SemverDialects::InvalidVersionError, input unless s == 'r'

            @revision << s

            return unless scanner.peek(1) =~ DIGIT
          when (s = scanner.scan(DIGITS))
            @revision << s.to_i
            return
          else
            raise SemverDialects::InvalidVersionError, input
          end
        end
      end
    end
  end
end
