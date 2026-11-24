# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module FixCode
          class Executor < SlashCommandTool
            extend ::Gitlab::Utils::Override

            NAME = 'FixCode'
            HUMAN_NAME = 'Fix Code'
            DESCRIPTION = 'Useful tool to fix source code.'
            RESOURCE_NAME = nil
            ACTION = 'fix'
            EXAMPLE = <<~TEXT
              Question: Fix the following code
              ```
              def hello_world
                putz('Hello, world!')
              end
              ```
              Picked tools: "FixCode" tool.
              Reason: The question has a code block in which we want to fix any mistakes and typos. "FixCode" tool can process this question.
            TEXT
            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::FixCode::Prompts::Anthropic,
              anthropic: ::Gitlab::Llm::Chain::Tools::FixCode::Prompts::Anthropic
            }.freeze

            PROMPT_TEMPLATE = [
              Utils::Prompt.as_system(
                <<~PROMPT
                  You are a software developer.
                  You can analyze the given source code or text for errors.
                  Provide code snippet for the fixed code.
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
                  %<file_content_reuse>s
                  Any code snippets in response should be formatted in markdown.
                PROMPT
              )
            ].freeze

            SLASH_COMMANDS = {
              '/fix' => {
                description: 'Fix any errors in the code',
                selected_code_without_input_instruction: 'Fix any errors in the code user ' \
                  'selected inside <selected_code></selected_code> tags.',
                selected_code_with_input_instruction: 'Fix %<input>s in the selected code inside ' \
                  '<selected_code></selected_code> tags.',
                input_without_selected_code_instruction: 'Fix the code provided by the user: %<input>s.'
              }
            }.freeze

            def self.slash_commands
              SLASH_COMMANDS
            end

            def unit_primitive
              'fix_code'
            end

            private

            def allow_blank_message?
              false
            end

            override :usage_event_name
            def usage_event_name
              'fix_code'
            end

            override :context_options
            def context_options
              { libraries: context.libraries }
            end

            def selected_text_options
              super.tap do |opts|
                opts[:file_content_reuse] =
                  if opts[:file_content].present?
                    "The new code should fit into the existing file, " \
                      "consider reuse of existing code in the file when generating new code."
                  else
                    ''
                  end
              end
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
