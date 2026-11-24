# frozen_string_literal: true

module Resolvers
  module Ai
    class UserClassicChatAccessResolver < BaseResolver
      type ::GraphQL::Types::Boolean, null: false

      def resolve
        return false unless current_user

        Ability.allowed?(current_user, :access_duo_classic_chat)
      end
    end
  end
end
