# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module WriteTests
          class Executor < SlashCommandTool
            extend ::Gitlab::Utils::Override

            NAME = 'WriteTests'
            HUMAN_NAME = 'Write Tests'
            DESCRIPTION = 'Useful tool to write tests for source code.'
            RESOURCE_NAME = nil
            ACTION = 'generate tests for'
            EXAMPLE = <<~TEXT
              Question: Write tests for this code
              ```
              def hello_world
                puts('Hello, world!')
              end
              ```
              Picked tools: "WriteTests" tool.
              Reason: The question has a code block for which we want to write tests. "WriteTests" tool can process this question.
            TEXT
            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::WriteTests::Prompts::Anthropic,
              anthropic: ::Gitlab::Llm::Chain::Tools::WriteTests::Prompts::Anthropic
            }.freeze

            PROMPT_TEMPLATE = [
              Utils::Prompt.as_system(
                <<~PROMPT
                  You are a software developer.
                  You can write new tests.
                  %<language_info>s
                PROMPT
              ),
              Utils::Prompt.as_user(
                <<~PROMPT.chomp
                  %<file_content>s
                  In the file user selected this code:
                  <selected_code>
                    %<selected_text>s
                  </selected_code>

                  %<input>s
                  Any code blocks in response should be formatted in markdown.
                PROMPT
              )
            ].freeze

            SLASH_COMMANDS = {
              '/tests' => {
                description: 'Write tests for the code',
                selected_code_without_input_instruction: 'Write tests for the code user selected inside ' \
                  '<selected_code></selected_code> tags.',
                selected_code_with_input_instruction: 'Write tests %<input>s for the code user selected inside ' \
                                        '<selected_code></selected_code> tags.',
                input_without_selected_code_instruction: 'Write tests for the code provided by the user: %<input>s.'
              }
            }.freeze

            def self.slash_commands
              SLASH_COMMANDS
            end

            def unit_primitive
              'write_tests'
            end

            private

            def allow_blank_message?
              false
            end

            override :usage_event_name
            def usage_event_name
              'write_tests'
            end

            override :context_options
            def context_options
              { libraries: context.libraries }
            end

            def authorize
              Utils::ChatAuthorizer.context(context: context).allowed?
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
