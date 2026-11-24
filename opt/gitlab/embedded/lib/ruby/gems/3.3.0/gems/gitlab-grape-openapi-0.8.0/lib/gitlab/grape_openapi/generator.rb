# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    class Generator
      attr_reader :tag_registry

      def initialize(options = {})
        @api_classes = Array(options[:api_classes]).reject do |api_class|
          Gitlab::GrapeOpenapi.configuration.excluded_api_classes.include?(api_class.name)
        end
        @schema_registry = SchemaRegistry.new
        @request_body_registry = RequestBodyRegistry.new
        @tag_registry = TagRegistry.new
      end

      def generate
        # Resolved before initialize_tags so an invalid config.info fails before any conversion runs.
        info = openapi_info
        initialize_tags

        {
          openapi: '3.0.0',
          info: info,
          tags: tag_registry.tags.sort_by { |t| t.fetch(:name, '') },
          servers: Gitlab::GrapeOpenapi.configuration.servers.map(&:to_h),
          paths: paths,
          components: {
            securitySchemes: security_schemes,
            schemas: schemas
          },
          security: security_schemes.keys.map { |s| { s => [] } }
        }
      end

      def security_schemes
        Gitlab::GrapeOpenapi.configuration.security_schemes.to_h do |scheme|
          [scheme.type, scheme.to_h]
        end
      end

      def initialize_tags
        @api_classes.each do |api_class|
          Converters::TagConverter.new(api_class, tag_registry).convert
        end
      end

      def paths
        all_routes = @api_classes.flat_map(&:routes)
        Converters::PathConverter.convert(all_routes, @schema_registry, @request_body_registry)
      end

      private

      def openapi_info
        hash = configured_info.to_h
        return hash unless blank?(hash[:title]) || blank?(hash[:version])

        raise ConfigurationError, "config.info must be set with at least a title and version"
      end

      def configured_info
        info = Gitlab::GrapeOpenapi.configuration.info

        case info
        when Models::Info then info
        when Hash then Models::Info.new(**info.transform_keys(&:to_sym))
        when nil then Models::Info.new
        else
          raise ConfigurationError,
            "config.info must be a Gitlab::GrapeOpenapi::Models::Info or Hash, got #{info.class}"
        end
      end

      def blank?(value)
        value.to_s.strip.empty?
      end

      def schemas
        entity_schemas = @schema_registry.schemas.transform_values(&:to_h)
        request_body_schemas = @request_body_registry.schemas

        collisions = entity_schemas.keys & request_body_schemas.keys
        raise ArgumentError, "Schema component name collision: #{collisions.join(', ')}" unless collisions.empty?

        entity_schemas.merge(request_body_schemas)
      end
    end
  end
end
