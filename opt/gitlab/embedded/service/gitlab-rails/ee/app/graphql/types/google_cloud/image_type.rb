# frozen_string_literal: true

module Types
  module GoogleCloud
    class ImageType < BaseScalar
      graphql_name 'GoogleCloudImage'
      description 'Represents a Google Cloud Image for GKE'

      GOOGLE_CLOUD_IMAGE_REGEXP = /^[a-z]+(_[a-z]*)?$\Z/

      def self.coerce_input(input_value, _context)
        unless input_value.match?(GOOGLE_CLOUD_IMAGE_REGEXP)
          raise GraphQL::CoercionError, "#{input_value.inspect} is not a valid image name"
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
