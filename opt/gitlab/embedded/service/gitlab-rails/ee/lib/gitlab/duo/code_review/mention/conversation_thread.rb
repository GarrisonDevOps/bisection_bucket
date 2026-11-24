# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Mention
        class ConversationThread
          include ::Gitlab::Utils::StrongMemoize

          def initialize(note, include_current: true, limit: nil, max_length: nil)
            @note = note
            @include_current = include_current
            @limit = limit
            @max_length = max_length
          end

          def notes
            note.discussion.notes
          end
          strong_memoize_attr :notes

          def messages
            selected_notes = include_current ? notes : notes.reject { |discussion_note| discussion_note.id == note.id }
            selected_notes = selected_notes.last(limit) if limit
            ActiveRecord::Associations::Preloader.new(records: selected_notes, associations: :author).call

            selected_notes.map do |discussion_note|
              ConversationMessage.render(discussion_note, max_length: max_length)
            end
          end

          private

          attr_reader :note, :include_current, :limit, :max_length
        end
      end
    end
  end
end
