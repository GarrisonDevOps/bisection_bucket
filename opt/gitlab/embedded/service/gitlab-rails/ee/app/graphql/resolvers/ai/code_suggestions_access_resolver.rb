# frozen_string_literal: true

module Resolvers
  module Ai
    class CodeSuggestionsAccessResolver < BaseResolver
      type ::GraphQL::Types::Boolean, null: false

      def resolve
        return false unless current_user

        Feature.enabled?(:ai_duo_code_suggestions_switch, :instance, type: :ops) &&
          Ability.allowed?(current_user, :access_code_suggestions)
      end
    end
  end
end
