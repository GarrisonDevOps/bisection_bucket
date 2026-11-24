# frozen_string_literal: true

module Gitlab
  module Llm
    module Concerns
      module AllowedParams
        ANTHROPIC_PARAMS = %i[temperature max_tokens_to_sample stop_sequences].freeze
        VERTEX_PARAMS = %i[temperature maxOutputTokens topK topP].freeze

        ALLOWED_PARAMS = {
          anthropic: ANTHROPIC_PARAMS,
          vertex: VERTEX_PARAMS,
          litellm: ANTHROPIC_PARAMS
        }.freeze

        TRACKING_CLASS_NAMES = {
          anthropic: 'Gitlab::Llm::Anthropic::Client',
          vertex: 'Gitlab::Llm::VertexAi::Client',
          litellm: 'Gitlab::Llm::AiGateway::Client'
        }.freeze
      end
    end
  end
end
