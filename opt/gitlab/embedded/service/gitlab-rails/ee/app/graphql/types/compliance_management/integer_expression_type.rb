# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- We just need to list down all types of requirement controls so no auth required
module Types
  module ComplianceManagement
    class IntegerExpressionType < Types::BaseObject
      graphql_name 'IntegerExpression'
      description 'An expression with an integer value.'

      implements Interfaces::ExpressionInterface

      field :value, GraphQL::Types::Int, null: false, description: 'Integer value of the expression.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
