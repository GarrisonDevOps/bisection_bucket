# frozen_string_literal: true

module Resolvers
  module Ai
    class SlashCommandsResolver < BaseResolver
      type [::Types::Ai::SlashCommandType], null: true

      argument :url, GraphQL::Types::String, required: true, description: 'URL of the page the user is currently on.'

      def resolve(url:)
        user = context[:current_user]
        ::Ai::SlashCommandsService.new(user, url).available_commands
      end
    end
  end
end
