# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module FixCode
          module Prompts
            class Anthropic
              include Concerns::AnthropicPrompt

              def self.prompt(variables)
                {
                  prompt: Utils::Prompt.role_conversation(
                    Utils::Prompt.format_conversation(
                      ::Gitlab::Llm::Chain::Tools::FixCode::Executor::PROMPT_TEMPLATE,
                      variables)
                  )
                }
              end
            end
          end
        end
      end
    end
  end
end
