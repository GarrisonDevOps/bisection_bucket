# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- No specialized authorization needed to see slash command data
    class SlashCommandType < Types::BaseObject
      graphql_name 'SlashCommand'
      description "Duo Chat slash command"

      field :description, GraphQL::Types::String, null: false,
        description: 'Description of what the slash command does.'
      field :name, GraphQL::Types::String, null: false,
        description: 'Name of the slash command.'
      field :should_submit, GraphQL::Types::Boolean, null: false,
        description: 'Indicates whether the command should be submitted automatically when clicked.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
