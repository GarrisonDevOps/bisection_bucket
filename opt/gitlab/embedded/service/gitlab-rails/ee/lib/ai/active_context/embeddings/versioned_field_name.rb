# frozen_string_literal: true

module Ai
  module ActiveContext
    module Embeddings
      class VersionedFieldName
        InvalidFieldName = Class.new(StandardError)

        FIELD_FORMAT = /^(?<base>[a-z0-9_]+)_v(?<version>\d+)$/

        DEFAULT_FIELD_NAME = 'embeddings_v1'

        def initialize(current_field_name = nil)
          @current_field_name = current_field_name
        end

        def next_field_name
          return DEFAULT_FIELD_NAME unless current_field_name

          match = current_field_name.match(FIELD_FORMAT)

          unless match
            raise InvalidFieldName,
              "Field name '#{current_field_name}' does not match expected format (e.g., '#{DEFAULT_FIELD_NAME}')"
          end

          "#{match[:base]}_v#{match[:version].to_i + 1}"
        end

        private

        attr_reader :current_field_name
      end
    end
  end
end
