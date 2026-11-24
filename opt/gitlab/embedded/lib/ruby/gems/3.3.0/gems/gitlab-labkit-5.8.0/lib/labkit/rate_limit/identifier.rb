# frozen_string_literal: true

module Labkit
  module RateLimit
    # Identifier is a value object wrapping a hash of key-value pairs that
    # describe the caller (e.g. user, ip, endpoint).
    # Endpoint values are normalised at construction time (query string stripped).
    class Identifier
      InvalidKeyError = Class.new(ArgumentError)
      DuplicateNormalizedKeyError = Class.new(InvalidKeyError)

      # Normalize an endpoint value: strip query string.
      def self.normalize_endpoint(value)
        return value unless value.is_a?(String)

        value.split("?", 2).first
      end

      attr_reader :attributes

      def initialize(attributes = {})
        normalised = {}
        original_keys = {}

        attributes.each do |key, value|
          unless key.respond_to?(:to_sym)
            # Reject keys such as nil, 42, and [] instead of leaking NoMethodError;
            # identifiers must have a canonical symbol key for matching and serialization.
            raise InvalidKeyError, "Identifier key #{key.inspect} must respond to #to_sym"
          end

          normalised_key = key.to_sym
          if normalised.key?(normalised_key)
            # Reject { user: 1, "user" => 2 } (and its reverse order): silently
            # choosing a value would make the rate-limit bucket insertion-order dependent.
            raise DuplicateNormalizedKeyError,
              "Identifier keys normalize to the same key #{normalised_key.inspect}: " \
                "#{original_keys[normalised_key].inspect} and #{key.inspect}"
          end

          original_keys[normalised_key] = key
          normalised[normalised_key] = value
        end

        normalised[:endpoint] = self.class.normalize_endpoint(normalised[:endpoint]) if normalised.key?(:endpoint)
        @attributes = normalised.freeze
      end

      # Return the value for a characteristic key.
      def [](key)
        @attributes[key.to_sym]
      end

      # Serialize to a plain Hash suitable for JSON logging.
      def to_h
        @attributes.transform_keys(&:to_s)
      end

      def ==(other)
        other.is_a?(Identifier) && other.attributes == @attributes
      end
    end
  end
end
