# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Converters
      # Maps the media types a route declares via `produces` to the OpenAPI
      # schema describing that response body.
      #
      # Media types the gem cannot describe resolve to `nil` so callers skip
      # them instead of guessing.
      class MediaTypeResolver
        BINARY_SCHEMA = { type: 'string', format: 'binary' }.freeze
        TEXT_SCHEMA = { type: 'string' }.freeze

        OCTET_STREAM_MEDIA_TYPE = 'application/octet-stream'

        BINARY_MEDIA_TYPES = [
          'application/gzip',
          OCTET_STREAM_MEDIA_TYPE,
          'application/x-tar'
        ].freeze

        TEXT_MEDIA_TYPES = %w[application/yaml].freeze

        TEXT_PREFIX = 'text/'

        class << self
          # `produces` accepts a bare String as well as an Array, and a declared
          # type may carry parameters (`text/csv; charset=utf-8`) which are not
          # part of an OpenAPI content key.
          #
          # Downcased because type and subtype are case-insensitive (RFC 6838),
          # so the tables below can match on one spelling and the emitted content
          # key stays canonical.
          def normalize(declaration)
            Array(declaration).filter_map do |media_type|
              normalized = media_type.to_s.split(';').first&.strip&.downcase
              normalized unless normalized.nil? || normalized.empty?
            end.uniq
          end

          # `application/json` is handled by the entity `$ref` path
          #  unrecognized types return nil rather than guessing the type
          def schema_for(media_type)
            return BINARY_SCHEMA if BINARY_MEDIA_TYPES.include?(media_type)
            return TEXT_SCHEMA if TEXT_MEDIA_TYPES.include?(media_type) || media_type.start_with?(TEXT_PREFIX)

            nil
          end
        end
      end
    end
  end
end
