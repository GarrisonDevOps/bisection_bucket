# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module RefactorCode
          class Executor < SlashCommandTool
            extend ::Gitlab::Utils::Override

            NAME = 'RefactorCode'
            HUMAN_NAME = 'Refactor Code'
            DESCRIPTION = 'Useful tool to refactor source code.'
            RESOURCE_NAME = nil
            ACTION = 'refactor'
            EXAMPLE = <<~TEXT
              Question: Refactor the following code
              ```
              def hello_world
                puts('Hello, world!')
              end
              ```
              Picked tools: "RefactorCode" tool.
              Reason: The question has a code block which we want to refactor. "RefactorCode" tool can process this question.
            TEXT
            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::RefactorCode::Prompts::Anthropic,
              anthropic: ::Gitlab::Llm::Chain::Tools::RefactorCode::Prompts::Anthropic
            }.freeze

            PROMPT_TEMPLATE = [
              Utils::Prompt.as_system(
                <<~PROMPT
                  You are a software developer.
                  You can refactor code.
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
                  Any code blocks in response should be formatted in markdown.
                PROMPT
              )
            ].freeze

            SLASH_COMMANDS = {
              '/refactor' => {
                description: 'Refactor the code',
                selected_code_without_input_instruction: 'Refactor the code user selected inside ' \
                  '<selected_code></selected_code> tags.',
                selected_code_with_input_instruction: 'Refactor %<input>s in the selected code inside ' \
                                        '<selected_code></selected_code> tags.',
                input_without_selected_code_instruction: 'Refactor the code provided by the user: %<input>s.'
              }
            }.freeze

            def self.slash_commands
              SLASH_COMMANDS
            end

            def unit_primitive
              'refactor_code'
            end

            private

            def allow_blank_message?
              false
            end

            override :usage_event_name
            def usage_event_name
              'refactor_code'
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
