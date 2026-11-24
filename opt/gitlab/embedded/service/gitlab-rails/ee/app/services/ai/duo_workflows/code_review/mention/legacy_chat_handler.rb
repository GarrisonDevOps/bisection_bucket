# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      module Mention
        class LegacyChatHandler < BaseHandler
          def execute
            progress_note = create_progress_note

            response = execute_chat_request(prepare_prompt_message)
            create_note_on(parse_response(response.response_body))
          ensure
            progress_note&.destroy
          end

          private

          def create_progress_note
            ::SystemNotes::MergeRequestsService.new(
              noteable: note.noteable,
              container: note.project,
              author: duo_code_review_bot
            ).duo_code_review_chat_started(note.discussion)
          end

          def prepare_prompt_message
            author = note.author
            thread = author.ai_conversation_threads.create!(conversation_type: :duo_code_review)
            prompt_message = nil
            notes = note.discussion.notes

            notes.each_with_index do |discussion_note, index|
              # We skip notes that are not mentioning the bot as we don't need it included
              # in the context we send with our chat request.
              next unless discussion_note.duo_bot_mentioned? || discussion_note.authored_by_duo_bot?

              role =
                if discussion_note.authored_by_duo_bot?
                  ::Gitlab::Llm::AiMessage::ROLE_ASSISTANT
                else
                  ::Gitlab::Llm::AiMessage::ROLE_USER
                end

              content = build_note_content(discussion_note, index == notes.size - 1)

              # We set the MR object as the resource so that it's accessible if Duo Chat decides
              # to utilize the merge_request_reader tool with identifier type "current".
              prompt_message = save_prompt_message(author, role, discussion_note.noteable, content, thread)
            end

            prompt_message
          end

          def build_note_content(discussion_note, last_note)
            content = discussion_note.note

            return content unless discussion_note.diff_note?

            # NOTE: We currently can't handle consequent messages from the same role so we need to
            #   append the extra instruction to the user message.
            #   We could change this once https://gitlab.com/gitlab-org/gitlab/-/issues/517435 gets fixed.
            last_note ? ::Gitlab::Llm::Utils::CodeSuggestionFormatter.append_prompt(content) : content
          end

          def parse_response(response_body)
            return response_body unless note.diff_note?

            ::Gitlab::Llm::Utils::CodeSuggestionFormatter.parse(response_body)[:body]
          end

          def save_prompt_message(user, role, resource, content, thread)
            prompt_message = ::Gitlab::Llm::ChatMessage
              .new(
                ai_action: 'chat',
                user: user,
                content: content,
                role: role,
                context: ::Gitlab::Llm::AiMessageContext.new(resource: resource),
                thread: thread
              )

            prompt_message.save!
            prompt_message
          end

          def execute_chat_request(prompt_message)
            ::Gitlab::Llm::Completions::Chat
              .new(
                prompt_message,
                nil,
                additional_context: additional_context,
                is_duo_code_review: true
              )
              .execute
          end

          # Non-diff notes rely on Duo Chat's merge_request_reader tool for MR context. The reference format is
          # recognized by MergeRequestReader::Executor::SYSTEM_PROMPT, so the LLM can use the `iid` or `reference`
          # identifier type when it does not use "current".
          def additional_context
            if note.diff_note?
              {
                id: note.latest_diff_file_path,
                category: 'file',
                content: note.raw_truncated_diff_lines
              }
            else
              {
                id: 'reference',
                category: 'merge_request',
                content: "!#{note.noteable.iid}"
              }
            end
          end
        end
      end
    end
  end
end
