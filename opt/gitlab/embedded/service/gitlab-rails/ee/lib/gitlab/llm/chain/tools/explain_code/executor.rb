# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module ExplainCode
          class Executor < SlashCommandTool
            extend ::Gitlab::Utils::Override

            NAME = 'ExplainCode'
            HUMAN_NAME = 'Explain Code'
            DESCRIPTION = 'Useful tool to explain code snippets and blocks.'
            RESOURCE_NAME = nil
            ACTION = 'explain'
            EXAMPLE = "Question: How would you improve the " \
                      "```def hello_world\nputs('Hello, world!\\n\');\nend``` code? " \
                      'Picked tools: "ExplainCode" tool. ' \
                      'Reason: The question has a code block that needs improvement. "ExplainCode" tool ' \
                      'can process this question.'
            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::ExplainCode::Prompts::Anthropic,
              anthropic: ::Gitlab::Llm::Chain::Tools::ExplainCode::Prompts::Anthropic
            }.freeze

            PROMPT_TEMPLATE = [
              Utils::Prompt.as_system(
                <<~PROMPT
                  You are a software developer.
                  You can explain code snippets.
                  %<language_info>s
                PROMPT
              ),
              Utils::Prompt.as_user(
                <<~PROMPT.chomp
                  %<file_content>s
                  Here is the code user selected:
                  <selected_code>
                    %<selected_text>s
                  </selected_code>

                  %<input>s
                  Any code blocks in response should be formatted in markdown.
                PROMPT
              )
            ].freeze

            SLASH_COMMANDS = {
              '/explain' => {
                description: 'Explain the code',
                selected_code_without_input_instruction: 'Explain the code user selected inside ' \
                  '<selected_code></selected_code> tags.',
                selected_code_with_input_instruction: 'Explain %<input>s user selected inside ' \
                  '<selected_code></selected_code> tags.',
                input_without_selected_code_instruction: 'Explain the input provided by the user: %<input>s.'
              }
            }.freeze

            def self.slash_commands
              SLASH_COMMANDS
            end

            def unit_primitive
              'explain_code'
            end

            private

            def allow_blank_message?
              false
            end

            override :usage_event_name
            def usage_event_name
              'explain_code'
            end

            def authorize
              Utils::ChatAuthorizer.context(context: context).allowed?
            end

            def resource_name
              nil
            end

            def ai_request
              context.ai_request
            end
          end
        end
      end
    end
  end
end
