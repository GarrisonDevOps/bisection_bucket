# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CommandValidators
      # Maps program names to their validators. Keyed by program binary
      # name, not tool name (run_command vs run_git_command).
      #
      # Unregistered programs fail closed -- pattern-based approval
      # requires a registered validator; exact-match always works.
      class Registry
        # make and curl are excluded: no subcommand structure means every
        # target/URL is arbitrary under `*`, with no safe read-only subset.
        VALIDATORS = {
          'git' => GitValidator,
          'npm' => NpmValidator,
          'docker' => DockerValidator,
          'bundle' => BundleValidator
        }.freeze

        class << self
          def validator_for(program)
            klass = VALIDATORS[program]
            return unless klass

            klass.new
          end

          def registered?(program)
            VALIDATORS.key?(program)
          end
        end
      end
    end
  end
end
