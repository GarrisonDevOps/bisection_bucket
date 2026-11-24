# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- We just need to list down all types of requirement controls so no auth required
module Types
  module ComplianceManagement
    class BooleanExpressionType < Types::BaseObject
      graphql_name 'BooleanExpression'
      description 'an expression with a boolean value.'

      implements Interfaces::ExpressionInterface

      field :value, GraphQL::Types::Boolean, null: false, description: 'Boolean value of the expression.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
