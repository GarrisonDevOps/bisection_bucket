# frozen_string_literal: true

module Ai
  # Service for checking if a file is excluded from AI processing based on duo_context_exclusion_settings
  class FileExclusionService < BaseService
    include Gitlab::Utils::StrongMemoize

    # Error reasons
    NO_PATH_PROVIDED = :no_path_provided
    INVALID_PATH = :invalid_path

    def initialize(project)
      @project = project
    end

    # Checks if the given file path is excluded based on project settings
    #
    # @param [Array<String>] file_paths The path(s) to check, relative to repository base
    # @return [ServiceResponse] Success with payload[:excluded] = true/false or Error
    def execute(file_paths)
      if file_paths.blank? || !file_paths.is_a?(Array)
        return ServiceResponse.error(
          message: 'File paths must be provided',
          reason: NO_PATH_PROVIDED
        )
      end

      check_paths(file_paths)
    end

    private

    attr_reader :project

    def check_paths(file_paths)
      results = file_paths.filter_map do |path|
        normalized_path = normalize_path(path)

        if normalized_path.present?
          { path: path, excluded: excluded?(normalized_path) }
        else
          { path: path, excluded: false } # if invalid path, not excluded
        end
      end

      ServiceResponse.success(
        payload: results
      )
    end

    def normalize_path(path)
      return if path.nil? || !path.is_a?(String)

      path = path.sub(%r{^/+}, '')

      # Basic validation to ensure path doesn't contain problematic patterns
      return if path.include?('..') || path.include?('\\') || path =~ /\A\s*\z/ || path =~ /[\x00-\x1F\x7F]/

      Pathname.new(path).cleanpath.to_s
    end

    def exclusion_rules
      return [] unless project_setting&.duo_context_exclusion_settings.present?

      project_setting.duo_context_exclusion_settings['exclusion_rules'] || []
    end
    strong_memoize_attr :exclusion_rules

    def project_setting
      project&.project_setting
    end

    def excluded?(path)
      return false if exclusion_rules.empty?

      excluded = false

      exclusion_rules.each do |rule|
        next unless rule_matches_path?(rule, path)

        # Check if path begins with an exclamation point to determine if it's an include rule
        excluded = !rule.start_with?('!')
      end

      excluded
    end

    def rule_matches_path?(rule, path)
      return false unless rule.present?

      # Remove exclamation mark if it exists at the beginning for pattern matching
      pattern_path = rule.start_with?('!') ? rule[1..] : rule
      File.fnmatch(pattern_path, path)
    end
  end
end
