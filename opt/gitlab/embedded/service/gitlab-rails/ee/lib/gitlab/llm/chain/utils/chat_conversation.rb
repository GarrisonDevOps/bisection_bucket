# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Utils
        class ChatConversation
          LAST_N_MESSAGES = 50

          def initialize(user, thread)
            @user = user
            @thread = thread
          end

          # We save a maximum of 50 chat history messages
          # We save a max of 20k chars for each message prompt (~5k
          # tokens)
          # Response from Anthropic is max of 4096 tokens
          # So the max tokens we would ever send 9k * 50 = 450k tokens.
          # Max context window is 200k.
          # For now, no truncating actually happening here but we should
          # do that to make sure we stay under the limit.
          # https://gitlab.com/gitlab-org/gitlab/-/issues/452608
          def truncated_conversation_list(last_n: LAST_N_MESSAGES)
            conversations = successful_conversations
            conversations = deduplicate_roles(conversations)
            messages = sort_by_timestamp(conversations)

            return [] if messages.blank?

            # DCR doesn't set request_id in messages, hence the messages return the full list
            #   without excluding the last user role message.
            # Since the last user message is appended in `ReactExecutor`, we exclude it here.
            # See https://gitlab.com/gitlab-org/gitlab/-/issues/501150#note_2336430176 for more info.
            messages.pop if messages.last.role == Gitlab::Llm::AiMessage::ROLE_USER

            messages.last(last_n).map do |message, _|
              { role: message.role.to_sym, content: message.content,
                additional_context: message.extras['additional_context'],
                agent_scratchpad: message.extras['agent_scratchpad'] }
            end
          end

          private

          attr_reader :user, :thread

          # returns successful interactions with chat where both question and answer are present
          # messages are grouped into conversations based on request_id
          def successful_conversations
            ChatStorage.new(user, thread)
              .last_conversation
              .reject { |message| message.errors.present? || message.content.blank? }
              .group_by(&:request_id)
              .select { |_uuid, messages| messages.size > 1 }
          end

          def deduplicate_roles(conversations)
            conversations.each do |request_id, messages|
              messages_to_keep = []
              last_role = nil

              # we're iterating messages in conversations in reverse order
              # to keep the last message for each role
              messages.reverse_each do |message|
                messages_to_keep << message if message.role != last_role
                last_role = message.role
              end

              # apply reverse card second time to get the original order
              conversations[request_id] = messages_to_keep.reverse
            end

            conversations
          end

          def sort_by_timestamp(conversations)
            conversations.values.sort_by { |messages| messages.first.timestamp }.flatten
          end
        end
      end
    end
  end
end
