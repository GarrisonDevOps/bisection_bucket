# frozen_string_literal: true

module Types
  module ComplianceManagement
    module Interfaces
      module ExpressionInterface
        include GraphQL::Schema::Interface

        graphql_name 'ExpressionInterface'
        description 'Defines the common fields for all expressions.'

        field :field, String, null: false, description: 'Field the expression applies to.'
        field :operator, String, null: false, description: 'Operator of the expression.'
      end
    end
  end
end
