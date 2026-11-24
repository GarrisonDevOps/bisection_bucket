# frozen_string_literal: true

module Types
  module Ai
    module DapFactory
      # rubocop:disable Graphql/AuthorizeTypes -- authorized by the resolver that returns it
      class ValidationMessageType < BaseObject
        graphql_name 'DapFactoryValidationMessage'
        authorize_granular_token parent_authorizes: :update_ai_flow_trigger
        description 'A problem found in a DAP Software Factory configuration file.'

        field :path, GraphQL::Types::String,
          null: true,
          description: 'Dotted path to the setting, such as `stages.build.flow`. Null for the whole file.'

        field :code, GraphQL::Types::String,
          null: false,
          description: 'Machine-readable code for the problem.'

        field :message, GraphQL::Types::String,
          null: false,
          description: 'Description of the problem.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
