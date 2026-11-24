# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- We just need to list down all types of requirement controls so no auth required
module Types
  module ComplianceManagement
    class ControlExpressionType < Types::BaseObject
      graphql_name 'ControlExpression'
      description 'Represents a control expression.'

      field :expression, Types::ComplianceManagement::ExpressionUnion, null: false,
        description: 'Expression details for the control.'
      field :id, ID, null: false, description: 'ID for the control.'
      field :name, String, null: false, description: 'Name of the control.'
    end
  end
end

# rubocop: enable Graphql/AuthorizeTypes
