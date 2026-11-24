# frozen_string_literal: true

module Gitlab
  module Llm
    module Concerns
      module AvailableModels
        CLAUDE_3_5_SONNET = 'claude-3-5-sonnet-20240620'
        CLAUDE_3_5_SONNET_V2 = 'claude-3-5-sonnet-20241022'
        CLAUDE_3_7_SONNET = 'claude-3-7-sonnet-20250219'
        CLAUDE_3_HAIKU = 'claude-3-haiku-20240307'
        CLAUDE_3_5_HAIKU = 'claude-3-5-haiku-20241022'

        VERTEX_MODEL_CHAT = 'chat-bison'
        VERTEX_MODEL_CODE = 'code-bison'
        VERTEX_MODEL_CODECHAT = 'codechat-bison'
        VERTEX_MODEL_TEXT = 'text-bison'
        ANTHROPIC_MODELS = [CLAUDE_3_5_SONNET, CLAUDE_3_HAIKU, CLAUDE_3_5_HAIKU,
          CLAUDE_3_5_SONNET_V2, CLAUDE_3_7_SONNET].freeze
        VERTEX_MODELS = [VERTEX_MODEL_CHAT, VERTEX_MODEL_CODECHAT, VERTEX_MODEL_CODE, VERTEX_MODEL_TEXT].freeze

        AVAILABLE_MODELS = {
          anthropic: ANTHROPIC_MODELS,
          vertex: VERTEX_MODELS
        }.freeze
      end
    end
  end
end
