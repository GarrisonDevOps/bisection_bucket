# frozen_string_literal: true

require "json"
require "yaml"

require_relative "field_validator/config"
require_relative "field_validator/log_interceptor"
require_relative "field_validator/registry"

module Labkit
  module Logging
    ##
    # Runtime validator for logging fields.
    # Validates logged fields against standard and deprecated field lists.
    # This validator is automatically injected in non-production environments.
    # Offenses are collected during test runs and development.
    module FieldValidator
      class << self
        # Inject the validator into JsonLogger
        def inject!
          return if @injected

          # If the config file does not exist, we don't inject the validator.
          # To enable field validation in a repository, a config file must exist.
          return unless Config.config_file_exists?

          ::Labkit::Logging::JsonLogger.prepend(LogInterceptor)
          Kernel.at_exit { FieldValidator.process_violations }
          @injected = true
        end

        def initialize_todo_file
          Config.init_file!
          warn "Created .labkit_logging_todo.yml with skip_ci_failure enabled."
          warn ""
          warn "Next steps:"
          warn "1. Commit this file to source control"
          warn "2. Push and let CI run to generate offense logs"
          warn "3. Run: bundle exec labkit-logging fetch <project> <pipeline_id>"
          warn "4. Commit the populated todo file (skip_ci_failure will be removed automatically)"
        end

        def process_violations
          detected_offenses, new_offenses, removed_offenses = Registry.instance.finalize

          return if detected_offenses.empty? && new_offenses.empty? && removed_offenses.empty?

          in_ci = ENV["CI"] == "true"

          output_ndjson(detected_offenses) if in_ci

          # Auto-remove fixed offenses (not in CI to avoid race conditions)
          handle_removed_offenses(removed_offenses) if removed_offenses.any? && !in_ci

          if ENV["LABKIT_LOGGING_TODO_UPDATE"] == "true"
            handle_update(new_offenses)
          elsif new_offenses.any?
            handle_new_offenses(new_offenses)
          end
        end

        def clear_offenses!
          Registry.instance.clear!
        end

        private

        def handle_removed_offenses(removed_offenses)
          Config.update!([], removed_offenses)

          warn thank_you_message(removed_offenses)
        end

        def thank_you_message(removed_offenses)
          lines = [
            "",
            "=" * 80,
            "Thank you for improving our logging standards!",
            "=" * 80,
            "",
            "You fixed #{removed_offenses.size} deprecated field offense(s):",
            ""
          ]

          removed_offenses.each do |o|
            lines << "  - #{o['callsite']}: '#{o['deprecated_field']}' -> '#{format_standard_field(o['standard_field'])}'"
          end

          lines << ""
          lines << "#{Config.file_name} has been automatically updated."
          lines << "Please commit the changes to complete the cleanup."
          lines << ""
          lines << ("=" * 80)
          lines << ""

          lines.join("\n")
        end

        def handle_new_offenses(new_offenses)
          if ENV["CI"] == "true" && Config.skip_ci_failure?
            warn baseline_generation_message(new_offenses)
          else
            warn report_new_offenses(new_offenses)
            # Raise with exit code 2 to bypass the RSpec retry mechanism
            # See https://gitlab.com/gitlab-org/quality/tooling/labkit-spec/-/work_items/2
            raise SystemExit.new(2) # rubocop:disable Style/RaiseArgs
          end
        end

        def baseline_generation_message(offenses)
          lines = [
            "",
            "ℹ️  LabKit Logging: Baseline generation mode active",
            "",
            "Deprecated fields detected but skip_ci_failure is enabled.",
            "Offenses are being logged for collection.",
            "",
            "To establish baseline:",
            "  bundle exec labkit-logging fetch <project> <pipeline_id>",
            "",
            "Documentation: https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/blob/master/doc/FIELD_STANDARDIZATION.md",
            "",
            "--- Offenses Summary ---",
            "Total offenses: #{offenses.size} across #{offenses.map { |o| o['callsite'] }.uniq.size} file(s)", # rubocop:disable Rails/Pluck
            ""
          ]
          lines.join("\n")
        end

        def output_ndjson(detected_offenses)
          detected_offenses.each do |offense|
            puts "LABKIT_LOGGING_OFFENSE: #{JSON.generate(offense)}"
          end
        end

        def handle_update(new_offenses)
          updated_offenses = Config.update!(new_offenses)

          warn "\n✓ Updated .labkit_logging_todo.yml"
          warn "\n  Added #{new_offenses.size} new offenses ✓" if new_offenses.any?

          warn "Total: #{updated_offenses.size} offenses"
          warn "\nCommit the updated #{Config.file_name}."
        end

        def report_new_offenses(new_offenses)
          lines = [
            "",
            "=" * 80,
            "LabKit Logging Field Standardization: New Offenses Detected",
            "=" * 80,
            ""
          ]

          new_offenses.each do |o|
            lines << "#{o['callsite']}:#{o['lineno']}: '#{o['deprecated_field']}' is deprecated. Use '#{format_standard_field(o['standard_field'])}' instead."
          end

          lines << ""
          lines << ("=" * 80)
          lines << "Total: #{new_offenses.size} new offense(s) in #{new_offenses.map { |o| o['callsite'] }.uniq.size} file(s)" # rubocop:disable Rails/Pluck
          lines << ""
          lines << "See https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/blob/master/doc/FIELD_STANDARDIZATION.md#new-offenses-detected"
          lines << ("=" * 80)
          lines << ""

          lines.join("\n")
        end

        def format_standard_field(standard_field)
          const_name = Labkit::Fields.constant_name_for(standard_field)
          const_name ? "Labkit::Fields::#{const_name}" : standard_field
        end
      end
    end
  end
end

Labkit::Logging::FieldValidator.inject!
