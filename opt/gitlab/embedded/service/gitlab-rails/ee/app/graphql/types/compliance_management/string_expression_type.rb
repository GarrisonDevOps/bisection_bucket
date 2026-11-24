# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- We just need to list down all types of requirement controls so no auth required
module Types
  module ComplianceManagement
    class StringExpressionType < Types::BaseObject
      graphql_name 'StringExpression'
      description 'an expression with a string value.'

      implements Interfaces::ExpressionInterface

      field :value, GraphQL::Types::String, null: false, description: 'String value of the expression.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
