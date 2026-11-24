# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CommandValidators
      class BundleValidator < Base
        # Read/inspect subcommands only. Execute/persist subcommands (exec,
        # install, update, console, open, etc.) require exact-match approval
        # because positional args can achieve code execution.
        ALLOWED_SUBCOMMANDS = Set.new(%w[
          list show check info outdated version platform doctor viz
        ]).freeze

        ALLOWED_GLOBAL_OPTIONS = Set.new(%w[
          --verbose --no-color --retry --jobs
        ]).freeze

        # Defense-in-depth: block flags that redirect configuration or binary paths
        DANGEROUS_FLAGS = Set.new(%w[
          --gemfile --shebang --path --binstubs
        ]).freeze

        DANGEROUS_FLAG_PREFIXES = %w[
          --gemfile= --shebang= --path= --binstubs=
        ].freeze
      end
    end
  end
end
