# frozen_string_literal: true

require 'yaml'

module Analytics
  module Glql
    # Service for parsing incoming YAML configurations from API::Glql
    # It is then returned for GLQL processing
    class ParserService
      # Frontmatter format: ---\nconfig\n---\nquery
      # This regex handles both empty and non-empty config sections
      FRONTMATTER_REGEX = /\A---\n(?<config>.*?)\n---\n(?<query>.*)\z/m
      MAX_INPUT_SIZE = 10_000 # 10KB limit

      def initialize(glql_yaml:)
        raise ArgumentError, "Input exceeds maximum size" if glql_yaml.bytesize > MAX_INPUT_SIZE

        @glql_yaml = glql_yaml
      end

      def execute
        config, query = get_frontmatter_yaml
        config, query = get_standard_yaml if config.empty? || query.empty?

        { config: config, query: query }
      end

      private

      attr_reader :glql_yaml

      def get_frontmatter_yaml
        frontmatter_match = glql_yaml.match(FRONTMATTER_REGEX)
        return [{}, ''] unless frontmatter_match

        config_yaml = frontmatter_match[:config].strip
        query = frontmatter_match[:query].strip
        config = YAML.safe_load(config_yaml)
        # A blank, null, or comment-only config parses to nil and counts as empty.
        config = {} if config.nil?
        raise ArgumentError, 'Front matter configuration must be YAML key-value pairs' unless config.is_a?(Hash)

        [config, query]
      rescue Psych::Exception
        [{}, '']
      end

      # Pure YAML with a `query` key, otherwise the whole input is a plain query string
      def get_standard_yaml
        parsed = YAML.safe_load(glql_yaml)
        return [{}, glql_yaml.strip] unless parsed.is_a?(Hash) && parsed['query']

        query = parsed.delete('query')
        raise ArgumentError, 'Query must be a string' unless query.is_a?(String)

        [parsed, query]
      rescue Psych::Exception
        [{}, glql_yaml.strip]
      end
    end
  end
end
