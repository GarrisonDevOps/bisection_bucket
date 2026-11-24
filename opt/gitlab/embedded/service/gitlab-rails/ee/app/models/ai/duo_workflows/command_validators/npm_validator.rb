# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CommandValidators
      class NpmValidator < Base
        # Read/inspect subcommands only. Execute/persist subcommands (run,
        # install, exec, build, etc.) require exact-match approval because
        # positional args can achieve code execution without flags
        # (e.g. `npm config set script-shell evil`).
        ALLOWED_SUBCOMMANDS = Set.new(%w[
          list outdated audit view info search ls
          fund explain prefix root
        ]).freeze

        ALLOWED_GLOBAL_OPTIONS = Set.new(%w[
          --verbose --loglevel --json --long --parseable
        ]).freeze

        # Defense-in-depth: block flags that redirect execution or configuration
        DANGEROUS_FLAGS = Set.new(%w[
          --prefix --script-shell --userconfig --globalconfig
          --cache --registry
        ]).freeze

        DANGEROUS_FLAG_PREFIXES = %w[
          --prefix= --script-shell= --userconfig= --globalconfig=
          --cache= --registry=
        ].freeze
      end
    end
  end
end
