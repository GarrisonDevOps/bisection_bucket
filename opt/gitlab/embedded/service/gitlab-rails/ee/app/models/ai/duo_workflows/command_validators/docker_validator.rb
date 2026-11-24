# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CommandValidators
      class DockerValidator < Base
        # Read/inspect subcommands only. Execute/persist subcommands (run,
        # build, exec, compose, etc.) require exact-match approval because
        # positional args can achieve code execution or state changes.
        ALLOWED_SUBCOMMANDS = Set.new(%w[
          ps images logs inspect stats top port
          diff events history version info
        ]).freeze

        ALLOWED_GLOBAL_OPTIONS = Set.new(%w[
          --tls --tlsverify
        ]).freeze

        # Defense-in-depth: block flags that grant elevated container privileges
        DANGEROUS_FLAGS = Set.new(%w[
          --privileged --cap-add --security-opt
          --pid --device --userns --cgroupns
          --network
        ]).freeze

        DANGEROUS_FLAG_PREFIXES = %w[
          --privileged= --cap-add= --security-opt=
          --pid= --device= --userns= --cgroupns=
          --network=
        ].freeze
      end
    end
  end
end
