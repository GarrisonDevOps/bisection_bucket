# frozen_string_literal: true

module Types
  module Ai
    module DapFactory
      # rubocop:disable Graphql/AuthorizeTypes -- authorized by the resolver that returns it
      class ValidationResultType < BaseObject
        graphql_name 'DapFactoryValidationResult'
        authorize_granular_token parent_authorizes: :update_ai_flow_trigger
        description 'Result of validating DAP Software Factory configuration content.'

        field :valid, GraphQL::Types::Boolean,
          null: false,
          method: :valid?,
          description: 'Whether Sync would apply the content.'

        field :errors, [ValidationMessageType],
          null: false,
          description: 'Problems that stop Sync from applying the content.'

        field :warnings, [ValidationMessageType],
          null: false,
          description: 'Problems that Sync ignores.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
