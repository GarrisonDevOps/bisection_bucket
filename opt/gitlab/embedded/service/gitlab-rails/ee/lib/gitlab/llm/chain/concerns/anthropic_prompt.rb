# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Concerns
        module AnthropicPrompt
          CHARACTERS_IN_TOKEN = 4

          # 100_000 tokens limit documentation:  https://docs.anthropic.com/claude/reference/selecting-a-model
          TOTAL_MODEL_TOKEN_LIMIT = 100_000

          # leave a 20% for cases where 1 token does not exactly match to 4 characters
          INPUT_TOKEN_LIMIT = (TOTAL_MODEL_TOKEN_LIMIT * 0.8).to_i.freeze

          # approximate that one token is ~4 characters.
          MAX_CHARACTERS = (INPUT_TOKEN_LIMIT * CHARACTERS_IN_TOKEN).to_i.freeze

          ROLE_NAMES = {
            Llm::AiMessage::ROLE_USER => 'Human',
            Llm::AiMessage::ROLE_ASSISTANT => 'Assistant',
            Llm::AiMessage::ROLE_SYSTEM => ''
          }.freeze
        end
      end
    end
  end
end
