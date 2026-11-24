# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class PinnedVersionType < ::Types::BaseScalar
        graphql_name 'AiCatalogPinnedVersion'
        description <<~DESC
          Version that an AI catalog item consumer is pinned to.

          Represented as a string in the format `n.n.n`, where the major component is a
          non-zero integer without leading zeros, and the minor and patch components are
          non-negative integers without leading zeros. For example: `1.0.0`, `2.10.3`.
        DESC

        def self.coerce_input(input_value, _context)
          return if input_value.nil?

          unless input_value.is_a?(String) &&
              input_value.match?(::Ai::Catalog::ItemConsumer::PINNED_VERSION_PREFIX_REGEX)
            raise GraphQL::CoercionError,
              "#{input_value.inspect} is not a valid pinned version (expected format: n.n.n)"
          end

          input_value
        end

        def self.coerce_result(ruby_value, _context)
          return if ruby_value.nil?

          ruby_value.to_s
        end
      end
    end
  end
end
