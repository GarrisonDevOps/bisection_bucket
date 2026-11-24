# frozen_string_literal: true

module Types
  module Ai
    module SelfHostedModels
      class AcceptedModelsEnum < BaseEnum
        graphql_name 'AiAcceptedSelfHostedModels'
        description 'LLMs supported by the self-hosted model features.'

        value 'CODEGEMMA', 'CodeGemma Code: Suitable for code suggestions.', value: 'codegemma'
        value 'CODELLAMA', 'Code-Llama Instruct: Suitable for code suggestions.', value: 'codellama'
        value 'CODESTRAL', 'Codestral: Suitable for code suggestions.', value: 'codestral'
        value 'MISTRAL', 'Mistral: Suitable for code suggestions and duo chat.', value: 'mistral'
        value 'MIXTRAL', 'Mixtral: Suitable for code suggestions and duo chat.', value: 'mixtral'
        value 'DEEPSEEKCODER', description: 'Deepseek Coder base or instruct.', value: 'deepseekcoder'
        value 'LLAMA3', description: 'LLaMA 3: Suitable for code suggestions and duo chat.', value: 'llama3'
        value 'CLAUDE_3', description: 'Claude 3 model family, suitable for code generation and duo chat.',
          value: 'claude_3'
        value 'GPT', description: 'GPT: Suitable for code suggestions.', value: 'gpt'
        value 'GEMINI', description: 'Gemini: Suitable for duo agentic and non-agentic chat.', value: 'gemini'
        value 'EMBEDDING', description: 'Embedding: Suitable for semantic search.', value: 'embedding'
        value 'QWEN', description: 'Qwen: Suitable for code suggestions and duo chat.', value: 'qwen'
        value 'GENERAL', description: 'General: Any model suitable for code suggestions and duo chat.', value: 'general'
      end
    end
  end
end
