# frozen_string_literal: true

module Types
  module Security
    class CweIdentifierType < BaseScalar
      graphql_name 'CweIdentifier'
      description 'A CWE identifier.'

      PATTERN = /\ACWE-\d{1,5}\z/

      def self.coerce_input(value, _ctx)
        return value if value.is_a?(String) && value.match?(PATTERN)

        raise GraphQL::CoercionError, "#{value.inspect} is not a valid CWE identifier"
      end
    end
  end
end
