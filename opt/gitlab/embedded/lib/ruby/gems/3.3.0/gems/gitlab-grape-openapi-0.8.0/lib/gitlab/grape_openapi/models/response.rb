# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Models
      # https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.0.0.md#response-object
      class Response
        attr_reader :status_code, :description, :entity_class, :headers, :content_type

        # rubocop:disable Metrics/ParameterLists -- keyword arguments of a value object
        def initialize(
          status_code:, description:, entity_class: nil, schema_name: nil, headers: {},
          content_type: 'application/json', example: nil, examples: nil, is_array: false)
          @status_code = status_code.to_s
          @description = description
          @entity_class = entity_class
          @schema_name = schema_name
          @headers = headers
          @content_type = content_type
          @example = example
          @examples = examples
          @is_array = is_array
        end
        # rubocop:enable Metrics/ParameterLists

        def to_h(schema_registry)
          response = {
            description: description,
            content: {
              content_type => {
                schema: schema(schema_registry),
                example: @example,
                examples: @examples
              }.compact
            }
          }

          response[:headers] = headers if headers.any?

          response
        end

        private

        # `is_array: true` on a `success`/`entity` declaration means the route
        # renders a collection of the entity, not a single instance.
        def schema(schema_registry)
          reference = { '$ref' => schema_ref(schema_registry) }
          return reference unless @is_array

          { type: 'array', items: reference }
        end

        def schema_ref(schema_registry)
          normalized_name = @schema_name || schema_registry.register(entity_class, nil)
          "#/components/schemas/#{normalized_name}"
        end
      end
    end
  end
end
