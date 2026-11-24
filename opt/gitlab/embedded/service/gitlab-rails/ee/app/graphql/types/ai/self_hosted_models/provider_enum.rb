# frozen_string_literal: true

module Types
  module Ai
    module SelfHostedModels
      class ProviderEnum < BaseEnum
        graphql_name 'AiSelfHostedModelProvider'
        description 'Provider for a self-hosted model.'

        value 'API', description: 'API provider.', value: 'api'
        value 'BEDROCK', description: 'Amazon Bedrock provider.', value: 'bedrock'
        value 'VERTEX_AI', description: 'Gemini Enterprise Agent Platform provider.', value: 'vertex_ai'
      end
    end
  end
end
