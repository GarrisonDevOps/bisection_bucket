# frozen_string_literal: true

module Labkit
  module Logging
    module FieldValidator
      module Config
        FILE_NAME = '.labkit_logging_todo.yml'

        class << self
          def root
            @root ||= detect_root.freeze
          end

          def path
            @path ||= File.join(root, file_name).freeze
          end

          def file_name
            FILE_NAME
          end

          def deprecated_fields
            @deprecated_fields ||= Labkit::Fields::Deprecated.all.freeze
          end

          def load
            return {} unless config_file_exists?

            YAML.safe_load_file(path) || {}
          end

          def update!(new_offenses, removed_offenses = [])
            baseline_offenses = load.fetch('offenses', [])

            if removed_offenses.any?
              removed_keys = removed_offenses.to_set { |o| offense_key(o) }
              baseline_offenses = baseline_offenses.reject { |o| removed_keys.include?(offense_key(o)) }
            end

            updated = process_offenses(baseline_offenses + new_offenses)
            write_file({ 'offenses' => updated }, header: header)
            updated
          end

          def init_file!
            return if config_file_exists?

            content = <<~YAML
              # LabKit Logging Field Standardization TODO
              # This file tracks deprecated logging fields that need migration.
              #
              # To collect offenses from CI:
              #   bundle exec labkit-logging fetch <project> <pipeline_id>
              #
              # To collect offenses locally:
              #   LABKIT_LOGGING_TODO_UPDATE=true <local development process>
              #
              # More info: https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/blob/master/doc/FIELD_STANDARDIZATION.md

              skip_ci_failure: true  # Remove this flag once baseline is established

              offenses: []
            YAML

            write_file(nil, header: content)
          end

          def config_file_exists?
            File.exist?(path)
          end

          def skip_ci_failure?
            load.fetch('skip_ci_failure', false) == true
          end

          def detect_root
            return Bundler.root.to_s if defined?(Bundler) && Bundler.respond_to?(:root)
            return Rails.root.to_s if defined?(Rails) && Rails.respond_to?(:root)

            Dir.pwd
          end

          def header
            <<~HEADER
              # LabKit Logging Field Standardization TODO
              # AUTO-GENERATED FILE. DO NOT EDIT MANUALLY.
              #
              # This file tracks deprecated logging fields that need to be migrated to standard fields.
              # Each offense represents a file using a deprecated field that should be replaced.
              #
              # How to fix: https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/blob/master/doc/FIELD_STANDARDIZATION.md#how-to-fix-an-offense
              #
              # Adding offenses (if fixing is not immediately possible):
              #   LABKIT_LOGGING_TODO_UPDATE=true bundle exec rspec <spec_file>
              #
              # Regenerate entire TODO:
              #   Delete this file and run: LABKIT_LOGGING_TODO_UPDATE=true bundle exec rspec

            HEADER
          end

          private

          def write_file(data, header: self.header)
            content = data ? header + YAML.dump(data, line_width: -1) : header
            File.write(path, content)
          end

          def offense_key(offense)
            [offense['callsite'], offense['deprecated_field'], offense['logger_class']]
          end

          def process_offenses(offenses)
            offenses
              .uniq { |o| offense_key(o) }
              .sort_by { |o| offense_key(o) }
              .map { |o| format_offense(o) }
          end

          def format_offense(offense)
            {
              'logger_class' => offense['logger_class'],
              'callsite' => offense['callsite'],
              'deprecated_field' => offense['deprecated_field'],
              'standard_field' => standard_field_constant(offense['standard_field'])
            }
          end

          def standard_field_constant(standard_field)
            const_name = Labkit::Fields.constant_name_for(standard_field)
            const_name ? "Labkit::Fields::#{const_name}" : standard_field
          end
        end
      end
    end
  end
end
