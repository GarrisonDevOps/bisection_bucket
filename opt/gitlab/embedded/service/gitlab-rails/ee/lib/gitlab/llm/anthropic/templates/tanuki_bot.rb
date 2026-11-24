# frozen_string_literal: true

module Gitlab
  module Llm
    module Anthropic
      module Templates
        class TanukiBot
          OPTIONS = {
            max_tokens: 256
          }.freeze
          CONTENT_ID_FIELD = 'ATTRS'

          MAIN_PROMPT = <<~PROMPT
            The following are provided:

            * <question>: question
            * <doc>: GitLab documentation, and a %<content_id>s which will later be converted to URL
            * <example>: example responses

            Given the above:

            If relevant documentation is provided and you can answer the question using it, create a final answer.
              * Then return relevant "{{content_id}}" part for references, under the "{{content_id}}:" heading.

            If no documentation was provided: use your general knowledge to provide a helpful response. At the end of your response, add:
            “The question appears to be related to GitLab documentation, but no matching GitLab documentation was found. This response is based on the underlying LLM instead.”

            If you don’t know the answer from the provided documentation: use your general knowledge to provide a helpful response. At the end of your response, add:
            “The question appears to be related to GitLab documentation, but only limited GitLab documentation was found. This response is based on the underlying LLM instead."

            ---

            Question:
            <question>%<question>s</question>

            Documentation:
            %<content>s

            Example responses:
            <example>
              The documentation for configuring AIUL is present. The relevant sections provide step-by-step instructions on how to configure it in GitLab, including the necessary settings and fields. The documentation covers different installation methods, such as A, B and C.

              %<content_id>s:
              CNT-IDX-a52b551c78c6cc11a603e231b4e789b2
              CNT-IDX-27d7595271143710461371bcef69ed1e
            </example>
            <example>
              To configure AIUL in most CI/CD environments, you typically need to define environment variables, enable the integration settings in your admin panel, and validate the connection with test jobs. While exact steps vary by setup, it's essential to ensure correct permission scopes and network access.

              The question appears to be related to GitLab documentation, but no matching GitLab documentation was found. This response is based on the underlying LLM instead.

              %<content_id>s:
            </example>
            <example>
              To configure AIUL in most CI/CD environments, you typically need to define environment variables, enable the integration settings in your admin panel, and validate the connection with test jobs. While exact steps vary by setup, it's essential to ensure correct permission scopes and network access.

              The question appears to be related to GitLab documentation, but only limited GitLab documentation was found. This response is based on the underlying LLM instead.

              %<content_id>s:
              CNT-IDX-a52b551c78c6cc11a603e231b4e789b2
            </example>
          PROMPT

          def self.final_prompt(question:, documents:)
            content = documents_prompt(documents)

            conversation = Gitlab::Llm::Chain::Utils::Prompt.role_conversation([
              Gitlab::Llm::Chain::Utils::Prompt.as_user(main_prompt(question: question,
                content: content)),
              Gitlab::Llm::Chain::Utils::Prompt.as_assistant("FINAL ANSWER:")
            ])
            {
              prompt: conversation,
              options: {
                model: ::Gitlab::Llm::Anthropic::Client::CLAUDE_3_7_SONNET,
                inputs: {
                  question: question,
                  content_id: CONTENT_ID_FIELD,
                  documents: documents
                }
              }.merge(OPTIONS)
            }
          end

          def self.main_prompt(question:, content:)
            format(
              MAIN_PROMPT,
              question: question,
              content: content,
              content_id: CONTENT_ID_FIELD
            )
          end

          def self.documents_prompt(documents)
            documents.map do |document|
              <<~PROMPT.strip
                <doc>
                CONTENT: #{document[:content]}
                #{CONTENT_ID_FIELD}: CNT-IDX-#{document[:id]}
                </doc>
              PROMPT
            end.join("\n\n")
          end
        end
      end
    end
  end
end
