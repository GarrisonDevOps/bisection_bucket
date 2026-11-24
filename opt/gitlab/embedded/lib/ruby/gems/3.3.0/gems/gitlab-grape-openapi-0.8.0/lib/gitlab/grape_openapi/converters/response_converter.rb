# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Converters
      class ResponseConverter
        # RFC 9110 forbids a body on these, so a declared media type cannot
        # describe one.
        BODYLESS_STATUS_CODES = %w[204 304].freeze

        def initialize(route, schema_registry)
          @route = route
          @schema_registry = schema_registry
          @responses = {}
        end

        def convert
          extract_success_response
          extract_failure_responses
          @responses
        end

        private

        def extract_success_response
          entity_definition = success_definition

          case entity_definition
          when nil
            success_code = infer_success_code(with_body: declared_body?)
            add_simple_response(
              status_code: success_code,
              description: http_status_text(success_code),
              content: declared_content
            )
          when Class
            process_class_entity(entity_definition)
          when Hash
            process_hash_entity(entity_definition)
          when Array
            process_array_entities(entity_definition)
          end
        end

        def process_class_entity(entity_class)
          if EntityConverter.grape_entity?(entity_class)
            success_code = infer_success_code(with_body: true)
            add_response_with_entity(
              status_code: success_code,
              description: http_status_text(success_code),
              entity_class: entity_class,
              is_array: declared_is_array?
            )
          else
            success_code = infer_success_code(with_body: declared_body?)
            add_simple_response(
              status_code: success_code,
              description: http_status_text(success_code),
              content: declared_content
            )
          end
        end

        def process_hash_entity(entity_hash)
          if entity_hash[:model] && EntityConverter.grape_entity?(entity_hash[:model])
            add_response_with_entity(
              **hash_response(entity_hash),
              entity_class: entity_hash[:model]
            )
          elsif entity_hash[:schema]
            add_response_with_entity(
              **hash_response(entity_hash),
              schema_name: SchemaRegistry.file_component_name(entity_hash[:schema])
            )
          else
            status_code = entity_hash[:code] || infer_success_code(with_body: declared_body?)
            add_simple_response(
              status_code: status_code,
              description: entity_hash[:message] || http_status_text(status_code),
              content: declared_content
            )
          end
        end

        def hash_response(entity_hash)
          status_code = entity_hash[:code] || infer_success_code(with_body: true)
          {
            status_code: status_code,
            description: entity_hash[:message] || http_status_text(status_code),
            example: entity_hash[:example],
            examples: entity_hash[:examples],
            is_array: entity_hash.fetch(:is_array, declared_is_array?)
          }
        end

        def process_array_entities(entity_array)
          entity_array.each do |definition|
            case definition
            when Hash
              process_hash_entity(definition)
            when Class
              process_class_entity(definition)
            end
          end
        end

        def extract_failure_responses
          explicit_codes = Array(@route.http_codes)
          defined_status_codes = explicit_codes.filter_map { |c| (c.is_a?(Hash) ? c[:code] : c[0])&.to_i }
          http_codes = explicit_codes + infer_failure_codes.reject { |c| defined_status_codes.include?(c[:code]) }

          http_codes.each do |failure_def|
            case failure_def
            when Hash
              add_simple_response(
                status_code: failure_def[:code],
                description: failure_def[:message] || http_status_text(failure_def[:code])
              )
            when Array
              add_simple_response(
                status_code: failure_def[0],
                description: failure_def[1] || http_status_text(failure_def[0])
              )
            end
          end
        end

        def add_response_with_entity(
          status_code:, description:, entity_class: nil, schema_name: nil, example: nil, examples: nil,
          is_array: false)
          response = Models::Response.new(
            status_code: status_code,
            description: description,
            entity_class: entity_class,
            schema_name: schema_name,
            example: example,
            examples: examples,
            is_array: is_array
          )

          @responses[response.status_code] = response.to_h(@schema_registry)
        end

        # `content` is only ever passed for the success response, so failure
        # responses stay JSON.
        def add_simple_response(status_code:, description:, content: nil)
          key = status_code.to_s

          # `http_codes` (processed by `extract_failure_responses`) may include
          # success codes that are also covered by a `success`/`entity`
          # declaration. Preserve the existing response content (the entity
          # `$ref`) and only refresh the description, so the entity is not
          # silently dropped.
          if @responses[key]
            @responses[key][:description] = description
          else
            @responses[key] = { description: description }
            @responses[key][:content] = content if content && BODYLESS_STATUS_CODES.exclude?(key)
          end
        end

        # Whether the route describes a body, which decides between 200 and 204
        # for a DELETE.
        def declared_body?
          !declared_content.nil?
        end

        # The content map for a response is described with `produces` (or
        # `success File`) rather than an entity. `nil` when the route declares
        # nothing the gem can describe.
        def declared_content
          return @declared_content if defined?(@declared_content)

          @declared_content = build_declared_content
        end

        # If there is no schema for the declared type it is dropped as guessing
        # would misdescribe it. See MediaTypeResolver for the mapping.
        def build_declared_content
          content = declared_media_types.each_with_object({}) do |media_type, acc|
            schema = MediaTypeResolver.schema_for(media_type)
            acc[media_type] = { schema: schema } if schema
          end

          content unless content.empty?
        end

        # `is_array` can be declared standalone in the `desc` block (the common
        # form) instead of inline in the `success`/`entity` hash, in which case
        # it lands next to `produces` rather than in the success declaration.
        # Inline keys take precedence over this fallback.
        def declared_is_array?
          !!@route.settings.dig(:description, :is_array)
        end

        # An explicit `produces` overrides `success File`, matching grape-swagger existing behaviour.
        def declared_media_types
          produces = MediaTypeResolver.normalize(@route.settings.dig(:description, :produces))
          return produces if produces.any?
          return [] unless file_response?(success_definition)

          [MediaTypeResolver::OCTET_STREAM_MEDIA_TYPE]
        end

        # Recognizes `success File` in any of its shapes. Compared by name so if `File`
        # is passed as a String it matches. Aligns with grape-swagger's `file_response?`
        def file_response?(definition)
          case definition
          when Array then definition.any? { |item| file_response?(item) }
          when Hash then file_response?(definition[:model])
          else definition.to_s == 'File'
          end
        end

        def success_definition
          @route.options[:entity] || @route.options[:success]
        end

        # 204 means "No Content", so it only applies when the response has no
        # body to document. A DELETE route that renders an entity returns 200
        # at runtime (Grape's default for a rendered body).
        def infer_success_code(with_body: false)
          case http_method
          when 'POST' then 201
          when 'DELETE' then with_body ? 200 : 204
          else 200
          end
        end

        def infer_failure_codes
          codes = []
          codes << 404 if path_has_resource_parameters?
          codes << 400 if route_params.any? || %w[POST PUT PATCH].include?(http_method)
          codes.map { |code| { code: code, message: http_status_text(code) } }
        end

        def route_params
          @route.options[:params] || {}
        end

        def path_has_resource_parameters?
          # Splat segments count: `/packages/npm/*package_name` addresses a resource
          # just as `/packages/:id` does, so it earns the same inferred 404.
          NormalizedPath.new(@route.origin).path_parameter_names.any?
        end

        def http_status_text(code)
          Rack::Utils::HTTP_STATUS_CODES[code.to_i] || 'Success'
        end

        def http_method
          @route.request_method
        end
      end
    end
  end
end
