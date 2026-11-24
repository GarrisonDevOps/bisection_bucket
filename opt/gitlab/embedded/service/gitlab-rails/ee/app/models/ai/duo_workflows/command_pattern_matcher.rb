# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Token-based pattern matcher for command tool approvals.
    #
    # Constrains wildcard semantics so that `*` cannot match flag-shaped
    # tokens (those starting with `-`), closing the argument injection
    # surface at the pattern matching layer rather than requiring
    # per-program flag catalogs.
    #
    # Wildcard grammar:
    #   *         - matches exactly one token that does NOT start with `-`
    #   **        - matches zero or more tokens of any kind (including flags)
    #   --        - literal end-of-options marker; after it, `*` matches any token
    #   feature-* - embedded glob matched via File.fnmatch per-token,
    #               still rejects flag-shaped targets
    #   anything  - literal exact match
    #
    # Non-command tools should continue using File.fnmatch directly.
    class CommandPatternMatcher
      # @param pattern [String] the approval pattern (e.g., "git checkout *")
      # @param command [String] the command to match (e.g., "git checkout feature-branch")
      # @return [Boolean] true if the command matches the pattern
      def self.match?(pattern, command)
        new(pattern, command).match?
      end

      def initialize(pattern, command)
        @pattern_tokens = Shellwords.split(pattern)
        @command_tokens = Shellwords.split(command)
      rescue ArgumentError
        # Unbalanced quotes in either string -- no match (fail closed)
        @pattern_tokens = nil
      end

      def match?
        return false if @pattern_tokens.nil?

        match_tokens_from(0, 0, false)
      end

      private

      # Recursively matches pattern tokens against command tokens with memoization.
      # pi = pattern index, ci = command index,
      # past_separator = whether we've passed a `--` token
      def match_tokens_from(pi, ci, past_separator)
        return remaining_pattern_matches_empty?(pi) if ci >= @command_tokens.length
        return false if pi >= @pattern_tokens.length

        @memo ||= {}
        key = [pi, ci, past_separator]
        return @memo[key] if @memo.key?(key)

        @memo[key] = match_at(pi, ci, past_separator)
      end

      def match_at(pi, ci, past_separator)
        pt = @pattern_tokens[pi]

        if pt == '**'
          match_double_star(pi, ci, past_separator)
        elsif pt == '--'
          @command_tokens[ci] == '--' && match_tokens_from(pi + 1, ci + 1, true)
        elsif pt == '*'
          match_single_star(pi, ci, past_separator)
        elsif glob_token?(pt)
          match_glob(pt, pi, ci, past_separator)
        else
          pt == @command_tokens[ci] && match_tokens_from(pi + 1, ci + 1, past_separator)
        end
      end

      # `**` matches zero or more tokens of any kind (greedy with backtracking).
      def match_double_star(pi, ci, past_separator)
        (ci..@command_tokens.length).any? do |j|
          sep = past_separator || @command_tokens[ci...j].include?('--')
          match_tokens_from(pi + 1, j, sep)
        end
      end

      # `*` matches exactly one non-flag token, or any token past `--`.
      def match_single_star(pi, ci, past_separator)
        ct = @command_tokens[ci]
        return false if rejects_flag_target?(ct, past_separator)

        match_tokens_from(pi + 1, ci + 1, past_separator)
      end

      # Embedded glob (e.g., `feature-*`) -- fnmatch per-token, rejects
      # flag-shaped targets unless the pattern itself starts with `-`.
      def match_glob(pt, pi, ci, past_separator)
        ct = @command_tokens[ci]
        return false if rejects_flag_target?(ct, past_separator) && !flag_token?(pt)

        File.fnmatch(pt, ct, File::FNM_DOTMATCH) && match_tokens_from(pi + 1, ci + 1, past_separator)
      end

      # When command tokens are exhausted, succeed only if all remaining
      # pattern tokens can match zero commands (i.e., are all `**`).
      # When pi is also exhausted, the empty range makes all? return true.
      def remaining_pattern_matches_empty?(pi)
        (pi...@pattern_tokens.length).all? { |i| @pattern_tokens[i] == '**' }
      end

      def rejects_flag_target?(token, past_separator)
        flag_token?(token) && !past_separator
      end

      def flag_token?(token)
        token.start_with?('-')
      end

      def glob_token?(token)
        token != '*' && token != '**' && (token.include?('*') || token.include?('?') || token.include?('['))
      end
    end
  end
end
