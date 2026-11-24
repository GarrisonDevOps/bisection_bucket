# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      module Mention
        class BaseHandler
          include ::Gitlab::Utils::StrongMemoize

          def initialize(note)
            @note = note
          end

          def execute
            raise NotImplementedError
          end

          private

          attr_reader :note

          def duo_code_review_bot
            ::Users::Internal.in_organization(note.project.organization_id).duo_code_review_bot
          end
          strong_memoize_attr :duo_code_review_bot

          def create_note_on(content)
            return if content.blank?

            ::Notes::CreateService.new(
              note.project,
              duo_code_review_bot,
              noteable: note.noteable,
              note: content,
              in_reply_to_discussion_id: note.discussion_id,
              type: note.type
            ).execute
          end
        end
      end
    end
  end
end
