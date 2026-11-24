# frozen_string_literal: true

module Mutations
  module GitlabSubscriptions
    module BudgetCaps
      class UserOverrideInputType < Types::BaseInputObject
        graphql_name 'BudgetCapUserOverrideInput'
        description 'Input for a per-user budget cap override.'

        argument :user_id,
          ::Types::GlobalIDType[::User],
          required: false,
          description: 'Global ID of the user. Exactly one of `userId` or `username` must be provided.'

        argument :username, GraphQL::Types::String,
          required: false,
          validates: { allow_blank: false },
          experiment: { milestone: '19.5' },
          description: 'Username of the user. Exactly one of `userId` or `username` must be provided.'

        validates exactly_one_of: [:user_id, :username]

        argument :cap, GraphQL::Types::Float,
          required: true,
          validates: { numericality: { greater_than_or_equal_to: 0 } },
          description: 'Budget cap amount for the user.'

        argument :enabled, GraphQL::Types::Boolean,
          required: true,
          description: 'Whether the budget cap is enabled for the user.'
      end
    end
  end
end
