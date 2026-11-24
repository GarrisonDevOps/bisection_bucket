# frozen_string_literal: true

# Validates the structure of a Duo Code Review custom instructions file
# (`.gitlab/duo/mr-review-instructions.yaml`).
#
# Has no Rails or GitLab dependencies; can be loaded and run from a plain
# Ruby process or via the `gitlab:duo:lint_review_instructions` Rake task.

require 'yaml'

module Gitlab
  module Duo
    module Administration
      class ReviewInstructionsLinter
        DEFAULT_PATH = '.gitlab/duo/mr-review-instructions.yaml'
        INSTRUCTION_KEYS = %w[name instructions fileFilters].freeze

        private_constant :DEFAULT_PATH, :INSTRUCTION_KEYS

        Issue = Struct.new(:severity, :code, :message, :path, keyword_init: true) do
          def error?
            severity == :error
          end

          def warning?
            severity == :warning
          end

          def info?
            severity == :info
          end

          def to_s
            location = path ? " at #{path}" : ''
            "[#{severity.upcase} #{code}] #{message}#{location}"
          end
        end

        attr_reader :file_path, :issues

        def initialize(file_path = nil)
          @file_path = file_path || DEFAULT_PATH
          @issues = []
        end

        def run
          return self unless check_file_exists

          content = File.read(file_path)
          data = parse_yaml(content)
          return self unless data

          validate_root(data)
          self
        end

        def valid?
          issues.none?(&:error?)
        end

        def errors
          issues.select(&:error?)
        end

        def warnings
          issues.select(&:warning?)
        end

        def info
          issues.select(&:info?)
        end

        private

        def error(code, message, path: nil)
          issues << Issue.new(severity: :error, code: code, message: message, path: path)
        end

        def warn(code, message, path: nil)
          issues << Issue.new(severity: :warning, code: code, message: message, path: path)
        end

        def info_issue(code, message, path: nil)
          issues << Issue.new(severity: :info, code: code, message: message, path: path)
        end

        def check_file_exists
          return true if File.file?(file_path)

          error('E001', "File not found: #{file_path}")
          false
        end

        def parse_yaml(content)
          if content.strip.empty?
            warn('W007', 'File is empty; no instructions will be applied')
            return
          end

          YAML.safe_load(content, aliases: true)
        rescue Psych::SyntaxError => e
          error('E003', "Invalid YAML syntax: #{e.message}")
          nil
        rescue Psych::Exception => e
          error('E003', "YAML error: #{e.message}")
          nil
        end

        def validate_root(data)
          unless data.is_a?(Hash)
            error('E004', "Top-level YAML must be a mapping, got #{data.class}")
            return
          end

          unknown_keys = data.keys - ['instructions']
          unknown_keys.each do |key|
            warn('W001', "Unknown top-level key #{key.inspect}; expected only 'instructions'")
          end

          unless data.key?('instructions')
            error('E005', "Missing required top-level key 'instructions'")
            return
          end

          list = data['instructions']
          unless list.is_a?(Array)
            error('E006', "'instructions' must be a list, got #{list.class}")
            return
          end

          if list.empty?
            warn('W002', "'instructions' list is empty; no instructions will be applied")
            return
          end

          validate_items(list)
        end

        def validate_items(list)
          seen_names = {}

          list.each_with_index do |item, index|
            item_path = "instructions[#{index}]"

            unless item.is_a?(Hash)
              error('E007', "Entry must be a mapping, got #{item.class}", path: item_path)
              next
            end

            validate_required_fields(item, item_path)
            validate_file_filters(item, item_path)
            warn_unknown_keys(item, item_path)
            track_duplicate_name(item, item_path, seen_names)
          end
        end

        def validate_required_fields(item, item_path)
          error('E008', "Field 'name' must be a non-empty string", path: item_path) unless valid_string?(item['name'])

          return if valid_string?(item['instructions'])

          error('E009', "Field 'instructions' must be a non-empty string", path: item_path)
        end

        def valid_string?(value)
          value.is_a?(String) && !value.strip.empty?
        end

        def validate_file_filters(item, item_path)
          filters = item['fileFilters']

          if filters.nil?
            info_issue('I001', "Missing 'fileFilters'; the instruction applies to every file", path: item_path)
            return
          end

          unless filters.is_a?(Array)
            error('E011', "'fileFilters' must be a list, got #{filters.class}", path: item_path)
            return
          end

          if filters.empty?
            info_issue('I002', "'fileFilters' is empty; the instruction applies to every file", path: item_path)
            return
          end

          filters.each_with_index do |pattern, i|
            unless pattern.is_a?(String)
              error('E013', "fileFilters[#{i}] must be a string, got #{pattern.class}", path: item_path)
              next
            end

            error('E014', "fileFilters[#{i}] is blank", path: item_path) if pattern.strip.empty?
          end
        end

        def warn_unknown_keys(item, item_path)
          unknown = item.keys - INSTRUCTION_KEYS
          return if unknown.empty?

          warn(
            'W003',
            "Unknown keys: #{unknown.map(&:inspect).join(', ')}; expected #{INSTRUCTION_KEYS.join(', ')}",
            path: item_path
          )
        end

        def track_duplicate_name(item, item_path, seen_names)
          name = item['name']
          return if name.nil? || name.to_s.strip.empty?

          if seen_names.key?(name)
            warn('W004', "Duplicate name #{name.inspect} (also at #{seen_names[name]})", path: item_path)
          else
            seen_names[name] = item_path
          end
        end
      end
    end
  end
end
