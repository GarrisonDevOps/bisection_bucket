# frozen_string_literal: true

module Types
  module ComplianceManagement
    class ExpressionUnion < BaseUnion
      graphql_name 'ExpressionValue'
      description 'Represents possible value types for an expression.'

      TypeNotSupportedError = Class.new(StandardError)

      possible_types BooleanExpressionType, IntegerExpressionType, StringExpressionType

      def self.resolve_type(object, _context)
        case object[:value]
        when TrueClass, FalseClass
          Types::ComplianceManagement::BooleanExpressionType
        when Integer
          Types::ComplianceManagement::IntegerExpressionType
        when String
          Types::ComplianceManagement::StringExpressionType
        else
          raise TypeNotSupportedError, "Unexpected expression type: #{object[:value].class}"
        end
      end
    end
  end
end
