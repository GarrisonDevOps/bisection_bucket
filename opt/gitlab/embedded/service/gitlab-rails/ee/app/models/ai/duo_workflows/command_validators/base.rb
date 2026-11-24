# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CommandValidators
      # Base class for program-specific command validators.
      #
      # Validators are keyed by program name (e.g. "git", "npm"), not by
      # tool name (e.g. "run_command", "run_git_command"). This decoupling
      # means that when run_git_command is deprecated and all git commands
      # flow through run_command, the same GitValidator applies with zero
      # code changes.
      #
      # Subclasses configure validation by declaring constants:
      #
      #   ALLOWED_SUBCOMMANDS       - Set of allowed subcommands, or nil for
      #                               simple tools without subcommand structure.
      #   ALLOWED_GLOBAL_OPTIONS    - Set of allowed pre-subcommand flags.
      #   DANGEROUS_FLAGS           - Set of dangerous flag exact matches
      #                               (defense-in-depth for ** patterns).
      #   DANGEROUS_FLAG_PREFIXES   - Array of dangerous flag prefixes
      #                               (e.g. "--prefix=").
      #   DANGEROUS_COMPOUND_COMMANDS - Hash { 'subcommand' => Set['sub-arg'] }
      #                               for blocking compound commands like
      #                               "bisect run" or "npm exec".
      class Base
        # @param program [String] e.g. "git"
        # @param tokens [Array<String>] all arguments after the program name,
        #   including the subcommand (e.g. ["checkout", "main"])
        # @return [Boolean] true if the command is safe for pattern matching
        def safe_for_pattern_matching?(program:, tokens:) # rubocop:disable Lint/UnusedMethodArgument -- program: is part of the interface; subclasses may use it
          if subcommand_based?
            validate_subcommand_based(tokens)
          else
            validate_simple(tokens)
          end
        end

        private

        def subcommand_based?
          !allowed_subcommands.nil?
        end

        def allowed_subcommands
          read_constant(:ALLOWED_SUBCOMMANDS)
        end

        def allowed_global_options
          read_constant(:ALLOWED_GLOBAL_OPTIONS) || Set.new.freeze
        end

        def dangerous_flags
          read_constant(:DANGEROUS_FLAGS) || Set.new.freeze
        end

        # Array, not Set: prefixes are scanned with start_with?, so
        # Set membership gains nothing.
        def dangerous_flag_prefixes
          read_constant(:DANGEROUS_FLAG_PREFIXES) || [].freeze
        end

        def dangerous_compound_commands
          read_constant(:DANGEROUS_COMPOUND_COMMANDS) || {}.freeze
        end

        # Reads a constant from the subclass only (not ancestors), preventing
        # accidental inheritance from Object or other unrelated scopes.
        def read_constant(name)
          self.class.const_defined?(name, false) ? self.class.const_get(name, false) : nil
        end

        def validate_subcommand_based(tokens)
          global_options, subcommand, subcommand_args = split_tokens(tokens)

          unless subcommand
            log_rejection('no subcommand found', tokens)
            return false
          end

          unless allowed_subcommands.include?(subcommand)
            log_rejection("subcommand '#{subcommand}' not in allowlist", tokens)
            return false
          end

          unless global_options_allowed?(global_options)
            log_rejection("disallowed global option in #{global_options}", tokens)
            return false
          end

          if contains_dangerous_flags?(subcommand_args)
            log_rejection("dangerous flag in subcommand args #{subcommand_args}", tokens)
            return false
          end

          if compound_command_dangerous?(subcommand, subcommand_args)
            log_rejection("dangerous compound command: #{subcommand} #{subcommand_args.first}", tokens)
            return false
          end

          true
        end

        def validate_simple(tokens)
          if contains_dangerous_flags?(tokens)
            log_rejection("dangerous flag in #{tokens}", tokens)
            return false
          end

          true
        end

        # Splits tokens into [global_options, subcommand, subcommand_args].
        # Finds the first non-flag token; everything before it is a global
        # option. Flags with value args (e.g. `-c <val>`) have the value
        # classified as the subcommand -- safe because such flags aren't
        # in ALLOWED_GLOBAL_OPTIONS.
        def split_tokens(tokens)
          split_index = tokens.index { |t| !t.start_with?('-') }
          return [tokens, nil, []] if split_index.nil?

          global_options  = tokens[0...split_index]
          subcommand      = tokens[split_index]
          subcommand_args = tokens[(split_index + 1)..]

          [global_options, subcommand, subcommand_args]
        end

        def global_options_allowed?(global_options)
          global_options.all? { |opt| allowed_global_options.include?(opt) }
        end

        def contains_dangerous_flags?(args)
          flags = dangerous_flags
          prefixes = dangerous_flag_prefixes
          return false if flags.empty? && prefixes.empty?

          args.any? do |arg|
            flags.include?(arg) ||
              prefixes.any? { |prefix| arg.start_with?(prefix) }
          end
        end

        def compound_command_dangerous?(subcommand, subcommand_args)
          compounds = dangerous_compound_commands
          return false if compounds.empty?

          sub_args = compounds[subcommand]
          sub_args&.include?(subcommand_args.first) || false
        end

        def log_rejection(reason, tokens)
          Gitlab::AppLogger.debug(
            message: "#{self.class.name.split('::').last} rejected command for pattern matching: #{reason}",
            tokens: tokens
          )
        rescue StandardError
          # Logging is best-effort; do not fail validation if the logger
          # is unavailable (e.g. fast_spec_helper context).
        end
      end
    end
  end
end
