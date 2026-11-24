# frozen_string_literal: true

module Types
  module GoogleCloud
    class ProjectType < BaseScalar
      graphql_name 'GoogleCloudProject'
      description 'Represents a Google Cloud Compute project'

      # See https://cloud.google.com/resource-manager/reference/rest/v1/projects
      CLOUD_PROJECT_NAME_REGEX = /\A[a-z]([-a-z0-9]{4,28}[a-z0-9])?\z/

      def self.coerce_input(input_value, _context)
        unless input_value.match?(CLOUD_PROJECT_NAME_REGEX)
          raise GraphQL::CoercionError, "#{input_value.inspect} is not a valid project name"
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
