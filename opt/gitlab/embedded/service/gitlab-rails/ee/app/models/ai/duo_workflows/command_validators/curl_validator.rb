# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CommandValidators
      # Simple tool: URLs are positional args, no subcommand parsing.
      # ALLOWED_SUBCOMMANDS is intentionally not defined (nil = simple mode).
      class CurlValidator < Base
        # Defense-in-depth: block flags that write to disk, exfiltrate files,
        # redirect connections, or load configuration from files
        DANGEROUS_FLAGS = Set.new(%w[
          -o --output -O --remote-name
          -T --upload-file
          -K --config
          --connect-to --resolve
          -x --proxy --socks5
          -w --write-out
          --unix-socket --netrc-file
          --next -:
        ]).freeze

        DANGEROUS_FLAG_PREFIXES = %w[
          -o= --output=
          -T= --upload-file=
          -K= --config=
          --connect-to= --resolve=
          -x= --proxy= --socks5=
          -w= --write-out=
          --unix-socket= --netrc-file=
        ].freeze
      end
    end
  end
end
