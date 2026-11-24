# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module CommitReader
          module Prompts
            class Anthropic
              include Concerns::AnthropicPrompt

              def self.prompt(options)
                conversation = Utils::Prompt.role_conversation([
                  Utils::Prompt.as_user(options[:input]),
                  Utils::Prompt.as_assistant(options[:suggestions], "```json
                  \{
                    \"ResourceIdentifierType\": \"")
                ])

                {
                  prompt: conversation,
                  options: { model: ::Gitlab::Llm::Anthropic::Client::CLAUDE_3_HAIKU }
                }
              end
            end
          end
        end
      end
    end
  end
end
