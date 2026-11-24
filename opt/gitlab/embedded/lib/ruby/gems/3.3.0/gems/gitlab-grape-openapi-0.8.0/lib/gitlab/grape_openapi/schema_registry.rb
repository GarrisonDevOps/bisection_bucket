# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    class SchemaRegistry
      attr_reader :schemas

      SCHEMA_FILE_NAME = %r{\A[a-z0-9_]+(/[a-z0-9_]+)*\z}

      def self.file_component_name(name)
        name.to_s.split(%r{[/_]}).map(&:capitalize).join
      end

      def initialize
        @schemas = {}
        @file_paths = {}
      end

      # Registers the `<name>.json` schema found in `config.schema_paths` and
      # returns its component name.
      def register_file(name)
        unless SCHEMA_FILE_NAME.match?(name.to_s)
          raise SchemaFileError, "Invalid schema name #{name.inspect}: " \
            "use lowercase letters, digits and underscores, with '/' between segments"
        end

        path = find_schema_file(name)
        component = self.class.file_component_name(name)
        return component if @file_paths[component] == path

        raise SchemaFileError, "Schema #{name.inspect} collides with component #{component}" if @schemas.key?(component)

        @schemas[component] = deep_freeze(parse_schema_file(path))
        @file_paths[component] = path
        component
      end

      def register(entity_class, schema)
        normalized_name = normalize_entity_class(entity_class)
        if @file_paths.key?(normalized_name)
          raise SchemaFileError, "Entity #{entity_class.name} collides with schema file component #{normalized_name}"
        end

        return normalized_name if @schemas.key?(normalized_name)
        return normalized_name unless schema.is_a?(Models::Schema)

        @schemas[normalized_name] = schema
        normalized_name
      end

      def normalize_entity_class(entity_class)
        entity_class.name.delete(':')
      end

      private

      def find_schema_file(name)
        dirs = Gitlab::GrapeOpenapi.configuration.schema_paths
        path = dirs.map { |dir| File.join(dir, "#{name}.json") }.find { |candidate| File.file?(candidate) }
        return path if path

        searched = dirs.empty? ? 'config.schema_paths is empty' : "searched #{dirs.join(', ')}"
        raise SchemaFileError, "Schema file #{name.inspect} not found: #{searched}"
      end

      def parse_schema_file(path)
        schema = JSON.parse(File.read(path))
        return schema if schema.is_a?(Hash)

        raise SchemaFileError, "Schema file #{path} must contain a JSON object"
      rescue JSON::ParserError => e
        raise SchemaFileError, "Schema file #{path} is not valid JSON: #{e.message}"
      end

      def deep_freeze(value)
        case value
        when Hash then value.each_value { |item| deep_freeze(item) }
        when Array then value.each { |item| deep_freeze(item) }
        end
        value.freeze
      end
    end
  end
end
