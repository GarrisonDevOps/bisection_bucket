# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      module Mention
        class IntentContext
          include ::Gitlab::Utils::StrongMemoize

          THREAD_NOTES_LIMIT = 5
          NOTE_MAX_LENGTH = 500
          NOT_REVIEWER = 'not_reviewer'

          def initialize(note, review_bot:)
            @note = note
            @review_bot = review_bot
          end

          def to_h
            {
              thread: thread,
              thread_started_by_duo_review: thread_started_by_duo_review?,
              duo_review_state: duo_review_state
            }
          end

          private

          attr_reader :note, :review_bot

          def thread
            conversation_thread.messages.join("\n")
          end

          def thread_started_by_duo_review?
            first_note = conversation_thread.notes.first

            first_note.present? && first_note.id != note.id && first_note.authored_by_duo_bot?
          end

          def duo_review_state
            return NOT_REVIEWER unless merge_request

            reviewer&.state || NOT_REVIEWER
          end

          def conversation_thread
            ConversationThread.new(
              note,
              include_current: false,
              limit: THREAD_NOTES_LIMIT,
              max_length: NOTE_MAX_LENGTH
            )
          end
          strong_memoize_attr :conversation_thread

          def merge_request
            note.noteable if note.noteable.is_a?(::MergeRequest)
          end

          def reviewer
            merge_request.find_reviewer(review_bot)
          end
          strong_memoize_attr :reviewer
        end
      end
    end
  end
end
