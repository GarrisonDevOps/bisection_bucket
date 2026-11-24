# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CommandValidators
      class GitValidator < Base
        # Layer 1: Subcommand allowlist (true allowlist, deny-by-default).
        # Only these git subcommands are eligible for pattern-based approval.
        # Unknown subcommands require exact-match approval.
        ALLOWED_SUBCOMMANDS = Set.new(%w[
          add
          bisect
          blame
          branch
          checkout
          cherry-pick
          clean
          commit
          describe
          diff
          difftool
          fetch
          grep
          init
          log
          merge
          mv
          pull
          push
          rebase
          reflog
          remote
          reset
          restore
          revert
          rm
          show
          stash
          status
          switch
          tag
          worktree
        ]).freeze

        # Layer 2: Global option allowlist (true allowlist, deny-by-default).
        # Pre-subcommand flags must be in this set. Everything else is rejected,
        # which blocks -c, -C, --exec-path, --config-env, and any other
        # global that could execute code or redirect git's binary lookup.
        ALLOWED_GLOBAL_OPTIONS = Set.new(%w[
          --no-pager
          --bare
          --no-replace-objects
          --literal-pathspecs
          --glob-pathspecs
          --icase-pathspecs
          --no-optional-locks
          --no-advice
        ]).freeze

        # Layer 3: Dangerous subcommand flag denylist (defense-in-depth ONLY).
        # CommandPatternMatcher constrains `*` wildcards from matching
        # flag-shaped tokens, which covers most injection vectors at the
        # pattern layer. This denylist remains as defense-in-depth for
        # `**` patterns (which opt in to flag matching) and as a safety
        # net for any matcher bugs. See #602494.
        DANGEROUS_FLAGS = Set.new(%w[
          --upload-pack
          --receive-pack
          --exec
          -x
          --extcmd
          --template
          --open-files-in-pager
          -c
          --config
        ]).freeze

        DANGEROUS_FLAG_PREFIXES = %w[
          --upload-pack=
          --receive-pack=
          --exec=
          --extcmd=
          --template=
          --open-files-in-pager=
          -O
          -c=
          --config=
        ].freeze

        # `git bisect run <script>` executes an arbitrary script per bisection
        # step. Scoped to bisect only to avoid false positives on branches or
        # files named "run" (e.g. `git checkout run`).
        DANGEROUS_COMPOUND_COMMANDS = {
          'bisect' => Set.new(%w[run]).freeze
        }.freeze
      end
    end
  end
end
