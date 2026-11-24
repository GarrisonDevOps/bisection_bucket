# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      module Mention
        class CodeReviewHandler < BaseHandler
          def execute
            merge_request = note.noteable

            if merge_request.duo_code_review_progress_note.present?
              create_note_on(review_in_progress_note)
              return
            end

            RequestReviewFromBot.new(
              merge_request: merge_request,
              current_user: note.author,
              bot: duo_code_review_bot
            ).execute
          end

          private

          def review_in_progress_note
            ::Gitlab::Duo::CodeReview::Messages.review_in_progress
          end
        end
      end
    end
  end
end
