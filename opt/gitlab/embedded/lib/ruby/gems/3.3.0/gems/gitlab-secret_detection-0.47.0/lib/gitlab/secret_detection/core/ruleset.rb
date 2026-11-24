# frozen_string_literal: true

require 'toml-rb'
require 'logger'
require 're2'
require_relative '../utils/memoize'

module Gitlab
  module SecretDetection
    module Core
      class Ruleset
        include ::Gitlab::SecretDetection::Utils::StrongMemoize

        # RulesetParseError is thrown when the code fails to parse the
        # ruleset file from the given path
        RulesetParseError = Class.new(StandardError)

        # RulesetCompilationError is thrown when the code fails to compile
        # the predefined rulesets
        RulesetCompilationError = Class.new(StandardError)

        ERROR_MESSAGES = {
          version_extraction_failed: "Failed to extract Secret Detection Ruleset version from ruleset file",
          parse_failed: "Failed to parse local secret detection ruleset: %<error>s",
          fallback: "Failed to load custom secret detection ruleset. Using the default ruleset.",
          validation_failed: "Ruleset validation failed:\n%<errors>s",
          invalid_extension: "Ruleset file must have a .toml extension",
          empty_rules: "Rules must be a non-empty Array of [[rules]] tables",
          duplicate_ids: "Rule ids must be unique",
          rule_error: "rules[%<index>d]: %<error>s",
          rule_not_table: "Rule must be a toml table",
          invalid_id: "Rule id must be a non-empty String",
          empty_regex: "Rule regex must be a non-empty String",
          invalid_regex: "Rule regex is not valid: %<error>s",
          invalid_description: "Rule title or description must be a non-empty String",
          invalid_keywords: "Rule keywords must be either empty or an Array of non-empty Strings"
        }.freeze

        # RulesetValidationError is raised when a custom ruleset file fails validation
        class RulesetValidationError < RulesetParseError
          def initialize(errors)
            super(format(ERROR_MESSAGES[:validation_failed], errors: errors.join("\n")))
          end
        end

        # Default ruleset file path
        RULESET_FILE_PATH = File.expand_path('secret_push_protection_rules.toml', __dir__)

        RULESET_FILE_PATH_ENV = 'GITLAB_SD_RULESET_FILE_PATH'

        # Returns the rule title, or the rule description when the title is nil or blank.
        def self.finding_description(rule)
          title = rule[:title]
          title.is_a?(String) && !title.strip.empty? ? title : rule[:description]
        end

        def initialize(path: nil, logger: Logger.new($stdout))
          @path = path
          @logger = logger
        end

        def rules(force_fetch: false)
          return @rule_data unless @rule_data.nil? || force_fetch

          @rule_data = parse_ruleset
        end

        # Before a load, it reads the file at resolved_path.
        def extract_ruleset_version
          file_path = loaded_path || resolved_path
          return unless File.readable?(file_path)

          first_line = File.open(file_path, &:gets)
          first_line&.split(":")&.[](1)&.strip # Gets "0.24.3" from "# rule-set version: 0.24.3"
        rescue StandardError => e
          logger.error(message: ERROR_MESSAGES[:version_extraction_failed], error: e.message)
          nil
        end

        private

        attr_reader :logger, :loaded_path

        def parse_ruleset
          load_from(resolved_path)
        rescue RulesetParseError => e
          raise if resolved_path == RULESET_FILE_PATH

          log_fallback(e)
          load_from(RULESET_FILE_PATH)
        end

        def resolved_path
          return File.absolute_path(@path) if @path

          env_value = ENV.fetch(RULESET_FILE_PATH_ENV, '').strip
          env_value.empty? ? RULESET_FILE_PATH : File.absolute_path(env_value)
        end
        strong_memoize_attr :resolved_path

        def load_from(file_path)
          custom = file_path != RULESET_FILE_PATH

          logger.info(
            message: "Parsing #{custom ? 'custom' : 'bundled'} ruleset file",
            ruleset_path: file_path
          )
          check_toml_extension!(file_path) if custom

          rules_data = TomlRB.load_file(file_path, symbolize_keys: true).freeze
          validate_rules!(rules_data) if custom

          @loaded_path = file_path
          logger.info(
            message: "Ruleset details fetched for running Secret Detection scan",
            ruleset_path: file_path,
            total_rules: rules_data[:rules]&.length,
            ruleset_version: extract_ruleset_version,
            custom_ruleset: custom
          )
          rules_data[:rules].freeze
        rescue RulesetParseError
          raise
        # A deeply nested TOML file raises SystemStackError.
        rescue StandardError, SystemStackError => e
          logger.error(message: format(ERROR_MESSAGES[:parse_failed], error: e.message)) unless custom
          raise RulesetParseError, e
        end

        def check_toml_extension!(file_path)
          return if File.extname(file_path).casecmp?('.toml')

          raise RulesetValidationError, [ERROR_MESSAGES[:invalid_extension]]
        end

        # Ruleset validation ensuring it has all the required
        # fields. Applicable to custom ruleset input only.
        def validate_rules!(rules_data)
          rules = rules_data[:rules]
          raise RulesetValidationError, [ERROR_MESSAGES[:empty_rules]] unless rules.is_a?(Array) && !rules.empty?

          errors = rules.each_with_index.flat_map do |rule, index|
            rule_errors(rule).map { |error| format(ERROR_MESSAGES[:rule_error], index:, error:) }
          end

          if errors.empty? && rules.map { |rule| rule[:id] }.uniq.size < rules.size
            errors << ERROR_MESSAGES[:duplicate_ids]
          end

          raise RulesetValidationError, errors unless errors.empty?
        end

        def rule_errors(rule)
          return [ERROR_MESSAGES[:rule_not_table]] unless rule.is_a?(Hash)

          finding_description = self.class.finding_description(rule)
          keywords = rule[:keywords]

          errors = []
          errors << ERROR_MESSAGES[:invalid_id] unless non_empty_string?(rule[:id])
          errors << regex_error(rule[:regex])
          errors << ERROR_MESSAGES[:invalid_description] unless non_empty_string?(finding_description)

          unless keywords.nil? || (keywords.is_a?(Array) && keywords.all? { |keyword| non_empty_string?(keyword) })
            errors << ERROR_MESSAGES[:invalid_keywords]
          end

          errors.compact
        end

        def regex_error(regex)
          return ERROR_MESSAGES[:empty_regex] unless non_empty_string?(regex)

          # Without log_errors: false, RE2 writes the pattern to STDERR.
          compiled = RE2::Regexp.new(regex, log_errors: false)
          format(ERROR_MESSAGES[:invalid_regex], error: compiled.error) unless compiled.ok?
        end

        def non_empty_string?(value)
          value.is_a?(String) && !value.strip.empty?
        end

        def log_fallback(error)
          logger.error(
            message: ERROR_MESSAGES[:fallback],
            custom_ruleset_path: resolved_path,
            default_ruleset_path: RULESET_FILE_PATH,
            ruleset_path_env: RULESET_FILE_PATH_ENV,
            error_class: fallback_error_class(error),
            error_message: error.message
          )
        end

        # A validation error gets an unrelated cause when #rules runs inside a rescue block.
        def fallback_error_class(error)
          return error.class.name if error.is_a?(RulesetValidationError)

          (error.cause || error).class.name
        end
      end
    end
  end
end
