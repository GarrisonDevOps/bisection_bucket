# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Concerns
      module Serializable
        private

        def serializable?(value)
          return false if value.is_a?(Proc)
          return false if defined?(ActiveSupport::TimeWithZone) && value.is_a?(ActiveSupport::TimeWithZone)
          return false if value.is_a?(Time)

          true
        end

        # Symbol maps to OpenAPI `string`, so Symbol values must become strings too.
        # Otherwise a Symbol serializes as `:value` in YAML, which parsers read back as that string.
        def stringify_symbols(value)
          case value
          when Symbol then value.to_s
          when Array then value.map { |element| stringify_symbols(element) }
          else value
          end
        end
      end
    end
  end
end
