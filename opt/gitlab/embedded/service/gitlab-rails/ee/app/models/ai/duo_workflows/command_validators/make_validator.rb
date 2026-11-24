# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CommandValidators
      # Simple tool: targets are positional args, no subcommand parsing.
      # ALLOWED_SUBCOMMANDS is intentionally not defined (nil = simple mode).
      class MakeValidator < Base
        # Defense-in-depth: block flags that redirect make to different
        # files or directories
        DANGEROUS_FLAGS = Set.new(%w[
          -f --file --makefile
          -C --directory
          -I --include-dir
          -e --environment-overrides
        ]).freeze

        DANGEROUS_FLAG_PREFIXES = %w[
          -f= --file= --makefile=
          -C= --directory=
          -I= --include-dir=
          -e= --environment-overrides=
        ].freeze
      end
    end
  end
end
