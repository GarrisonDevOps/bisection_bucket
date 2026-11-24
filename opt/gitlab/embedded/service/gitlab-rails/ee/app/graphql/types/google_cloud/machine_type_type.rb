# frozen_string_literal: true

module Types
  module GoogleCloud
    class MachineTypeType < BaseScalar
      graphql_name 'GoogleCloudMachineType'
      description 'Represents a Google Cloud Compute machine type'

      GOOGLE_CLOUD_MACHINE_TYPE_REGEXP = /\A[a-z]([-a-z0-9]*[a-z0-9])?\z/

      def self.coerce_input(input_value, _context)
        unless input_value.match?(GOOGLE_CLOUD_MACHINE_TYPE_REGEXP)
          raise GraphQL::CoercionError, "#{input_value.inspect} is not a valid machine type name"
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
