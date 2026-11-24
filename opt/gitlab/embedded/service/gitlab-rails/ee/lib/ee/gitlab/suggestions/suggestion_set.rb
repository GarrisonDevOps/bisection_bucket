# frozen_string_literal: true

module EE
  module Gitlab
    module Suggestions
      module SuggestionSet
        extend ::Gitlab::Utils::Override

        override :authors
        def authors
          suggestions.map { |suggestion| suggestion_author(suggestion.note) }.uniq
        end

        private

        def suggestion_author(note)
          note.agent_session&.service_account || note.author
        end
      end
    end
  end
end
