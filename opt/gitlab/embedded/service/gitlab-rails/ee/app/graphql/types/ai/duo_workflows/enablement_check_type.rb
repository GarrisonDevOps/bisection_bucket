# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class EnablementCheckType < Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
        graphql_name 'DuoWorkflowEnablementCheck'
        description "Represents single Duo Agent Platform enablement check."

        authorize_granular_token parent_authorizes: :read_project

        field :name, GraphQL::Types::String,
          null: false,
          description: 'Name of the status check.'

        field :value, GraphQL::Types::Boolean,
          null: false,
          description: 'Whether the check was successful or not.'

        field :message, GraphQL::Types::String,
          null: true,
          description: 'Description of status check.'
      end
    end
  end
end
