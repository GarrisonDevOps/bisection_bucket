# frozen_string_literal: true

require 'forwardable'
require 'json_schemer'
require 'pathname'
require 'yaml'
require 'labkit/json_schema/ref_resolver'

module Labkit
  module UserExperienceSli
    Definition = Data.define(:user_experience_id, :description, :feature_category, :urgency, :apdex_threshold_s) do
      def initialize(user_experience_id:, description:, feature_category:, urgency:, apdex_threshold_s: nil)
        super
      end
    end

    class Registry
      extend Forwardable

      SCHEMA_PATH = File.expand_path('../../../config/user_experience_slis/schema.json', __dir__)

      def_delegator :@experiences, :empty?

      # @param dir [String, Pathname] Directory path containing YAML file definitions
      #   Defaults to 'config/user_experience_slis' relative to the calling application's root
      def initialize(dir: File.join("config", "user_experience_slis"))
        @dir = Pathname.new(Dir.pwd).join(dir)
        @experiences = load_on_demand
      end

      # Retrieve a definition experience given a user_experience_id.
      #
      # @param user_experience_id [String, Symbol] User experience SLI identifier
      # @return [Experience, nil] An experience if present, otherwise nil
      def [](user_experience_id)
        @experiences[user_experience_id.to_s]
      end

      private

      # Initialize a hash that loads experiences on-demand
      #
      # @return [Hash] Hash with lazy loading behavior
      def load_on_demand
        unless readable_dir?
          warn("Directory not readable: #{@dir}")
          return {}
        end

        Hash.new do |result, experience_id|
          experience = load_experience(experience_id.to_s)
          # we also store nil to memoize the value and avoid triggering load_experience again
          result[experience_id.to_s] = experience
        end
      end

      # Load a user experience SLI definition.
      #
      # @param experience_id [String] Experience identifier
      # @return [Experience, nil] Loaded experience or nil if not found/invalid
      def load_experience(experience_id)
        file_path = @dir.join("#{experience_id}.yml")

        unless file_path.exist?
          warn("Invalid User Experience definition: #{experience_id}")
          return nil
        end

        read_experience(file_path, experience_id)
      end

      def readable_dir?
        @dir.exist? && @dir.directory? && @dir.readable?
      end

      # Read and validate a definition experience file
      #
      # @param file_path [Pathname] Path to the definition file
      # @param experience_id [String] Expected experience ID
      # @return [Experience, nil] Parsed experience or nil if invalid
      def read_experience(file_path, experience_id)
        content = YAML.safe_load(file_path.read)
        return nil unless content.is_a?(Hash)

        return Definition.new(user_experience_id: experience_id, **content.transform_keys(&:to_sym)) if schema.valid?(content)

        warn("Invalid schema for #{file_path}")
        nil
      rescue Psych::SyntaxError => e
        warn("Invalid definition file #{file_path}: #{e.message}")
        nil
      rescue StandardError => e
        warn("Unexpected error processing #{file_path}: #{e.message}")
        nil
      end

      def schema
        @schema ||= begin
          schema = JSON.parse(File.read(SCHEMA_PATH))
          timeout = Labkit::UserExperienceSli.configuration.ref_resolver_timeout
          JSONSchemer.schema(schema, ref_resolver: Labkit::JsonSchema::RefResolver.new(timeout_s: timeout))
        end
      end

      def warn(message)
        logger.warn(component: self.class.name, message: message)
      end

      def logger
        Labkit::UserExperienceSli.configuration.logger
      end
    end
  end
end
