# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    class RequestBodyRegistry
      SCHEMA_PATH_PREFIX = '#/components/schemas/'

      attr_reader :schemas

      def initialize
        @schemas = {}
      end

      def register(schema, name:)
        return nil if schema.blank?

        if @schemas.key?(name) && @schemas[name] != schema
          raise ArgumentError, "Request body schema name '#{name}' is already registered"
        end

        @schemas[name] = schema

        { '$ref' => "#{SCHEMA_PATH_PREFIX}#{name}" }
      end
    end
  end
end
