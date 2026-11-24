# frozen_string_literal: true

require 'labkit/json_schema/ref_resolver'
require 'labkit/logging/json_logger'
require 'labkit/user_experience_sli/current'
require 'labkit/user_experience_sli/error'
require 'labkit/user_experience_sli/experience'
require 'labkit/user_experience_sli/null'
require 'labkit/user_experience_sli/registry'

module Labkit
  # Labkit::UserExperienceSli namespace module.
  #
  # This module is responsible for managing user experience SLIs, which are
  # specific events or activities within the application that are measured
  # and reported for performance monitoring and analysis.
  module UserExperienceSli
    # Configuration class for UserExperienceSli
    class Configuration
      attr_accessor :logger, :registry_path, :ref_resolver_timeout

      def initialize
        @logger = Labkit::Logging::JsonLogger.new($stdout)
        @registry_path = File.join("config", "user_experience_slis")
        @ref_resolver_timeout = 2
      end

      def feature_category_schema_path=(path)
        preload_feature_category_schema(path) if path
      end

      private

      def preload_feature_category_schema(path)
        internal_schema = JSON.parse(File.read(Registry::SCHEMA_PATH))
        ref_url = internal_schema.dig("properties", "feature_category", "$ref")
        return unless ref_url

        schema = parse_schema_json(read_schema_file(path), path)
        Labkit::JsonSchema::RefResolver.cache[ref_url] = schema
      end

      def read_schema_file(path)
        File.read(path)
      rescue StandardError => e
        raise(UserExperienceError, "Failed to read feature category schema file at '#{path}': #{e.message}")
      end

      def parse_schema_json(content, path)
        JSON.parse(content)
      rescue JSON::ParserError => e
        raise(UserExperienceError, "Failed to parse feature category schema JSON at '#{path}': #{e.message}")
      end
    end

    class << self
      def configuration
        @configuration ||= Configuration.new
      end

      def reset_configuration
        @configuration = nil
      end

      def configure
        yield(configuration) if block_given?
        # Reset registry when configuration changes to pick up new registry_path
        @registry = nil
      end

      def registry
        @registry ||= Registry.new(dir: configuration.registry_path)
      end

      def reset
        @registry = nil
        reset_configuration
      end

      # Retrieves a user experience using the experience_id.
      # It retrieves from the current context when available,
      # otherwise it instantiates a new experience with the definition
      # from the registry.
      #
      # @param experience_id [String, Symbol] The ID of the experience to retrieve.
      # @return [Experience, Null] The found experience or a Null object if not found (in production/staging).
      def get(experience_id)
        find_current(experience_id) || raise_or_null(experience_id)
      end

      # Starts a user experience using the experience_id.
      #
      # @param experience_id [String, Symbol] The ID of the experience to start.
      # @param extra [Hash] Additional data to include in the log event.
      # @return [Experience, Null] The started experience or a Null object if not found (in production/staging).
      def start(experience_id, **extra, &)
        get(experience_id).start(**extra, &)
      end

      # Records a past user experience by its duration atomically.
      #
      # @param experience_id [String, Symbol] The ID of the experience.
      # @param start_time [Time] The time when the experience started.
      # @param extra [Hash] Additional data to include in the log events.
      # @return [Experience, Null] The observed experience or a Null object if not found (in production/staging).
      def observed(experience_id, start_time:, **extra)
        definition = registry[experience_id]
        experience = definition ? Experience.new(definition) : raise_or_null(experience_id)
        experience.observed(start_time: start_time, **extra)
      end

      # Resumes a user experience using the experience_id.
      #
      # @param experience_id [String, Symbol] The ID of the experience to resume.
      # @return [Experience, Null] The started experience or a Null object if not found (in production/staging).
      def resume(experience_id, **extra, &)
        get(experience_id).resume(**extra, &)
      end

      private

      def raise_or_null(experience_id)
        return Null.instance unless %w[development test].include?(ENV['RAILS_ENV'])

        raise(NotFoundError, "User Experience #{experience_id} not found in the registry")
      end

      def find_current(experience_id)
        xp = Current.active_experiences[experience_id.to_s]
        return xp unless xp.nil?

        definition = registry[experience_id]
        Experience.new(definition) if definition
      end
    end
  end

  # Backward compatibility alias for the old module name.
  # This alias is kept to maintain compatibility with existing code.
  # See: https://gitlab.com/gitlab-com/gl-infra/observability/team/-/issues/4347
  CoveredExperience = UserExperienceSli
end
