# frozen_string_literal: true

module Types
  module GoogleCloud
    class RegionType < BaseScalar
      graphql_name 'GoogleCloudRegion'
      description 'Represents a Google Cloud Compute region'

      GOOGLE_CLOUD_REGION_NAME_REGEXP = /\A[a-z]+-[a-z]+\d+\z/

      def self.coerce_input(input_value, _context)
        unless input_value.match?(GOOGLE_CLOUD_REGION_NAME_REGEXP)
          raise GraphQL::CoercionError, "#{input_value.inspect} is not a valid region name"
        end

        input_value
      end

      def self.coerce_result(ruby_value, _context)
        # It's transported as a string, so stringify it
        ruby_value.to_s
      end
    end
  end
end
