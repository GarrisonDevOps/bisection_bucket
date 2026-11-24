# frozen_string_literal: true

module Gitlab
  module Llm
    module Templates
      class GenerateCommitMessage
        include Gitlab::Llm::Chain::Concerns::AnthropicPrompt

        SYSTEM_MESSAGE = Gitlab::Llm::Chain::Utils::Prompt.as_system(
          <<~PROMPT.chomp
            You are tasked with generating a commit message based on a git diff. The git diff will be provided to you, and your job is to analyze the changes and create an appropriate, concise, and informative commit message.
          PROMPT
        )
        USER_MESSAGE = Gitlab::Llm::Chain::Utils::Prompt.as_user(
          <<~PROMPT.chomp
          To generate an effective commit message, follow these steps:

            1. Analyze the diff carefully, noting:
              - Which files were modified
              - The nature of the changes (additions, deletions, modifications)
              - Any significant code or content changes
            2. Summarize the main purpose of the changes in a brief (50-72 characters) title line.
            3. If necessary, provide more detailed explanations in the body of the commit message, with each point on a new line prefixed by a hyphen (-).
            4. Focus on explaining the "why" behind the changes, not just the "what".
            5. Use the imperative mood for the title (e.g., "Add feature" instead of "Added feature").
            6. If the changes are related to a specific issue or ticket, include the reference (e.g., "Fixes #123").

            Structure your commit message as follows:
            ```
            Title line

            - Detailed explanation point 1
            - Detailed explanation point 2
            - ...
            ```

            <example_diff>
            diff --git a/README.md b/README.md
            index c1788657b95998a2f177a4f86d68a60f2a80117f..da818fca1c2742de5ef4090cb440d92c11d41ae7 100644
            --- a/CONTRIBUTING.md
            +++ b/CONTRIBUTING.md
            @@ -6,7 +6,7 @@ Hello world
            Unchanged line

            -Removed line
            +Added line

            ## Another unchanged line
            </example_diff>

            <example_commit_message>
            Updated README.md

            - Changed `Removed line` to `Added line`
            </example_commit_message>

            Only return the commit message.

            <git_diff>
            ```
            %<diff>s
            ```
            </git_diff>
          PROMPT
        )

        def initialize(merge_request)
          @merge_request = merge_request
        end

        def to_prompt
          {
            messages: Gitlab::Llm::Chain::Utils::Prompt.role_conversation(
              Gitlab::Llm::Chain::Utils::Prompt.format_conversation([USER_MESSAGE], variables)
            ),
            system: Gitlab::Llm::Chain::Utils::Prompt.no_role_text([SYSTEM_MESSAGE], {}),
            model: ::Gitlab::Llm::Anthropic::Client::CLAUDE_3_5_SONNET
          }
        end

        def variables
          {
            diff: extracted_diff.truncate_words(10000)
          }
        end

        private

        attr_reader :merge_request

        def extracted_diff
          merge_request.raw_diffs.to_a.map(&:diff).join("\n")
        end
      end
    end
  end
end
