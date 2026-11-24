# frozen_string_literal: true

module Gitlab
  module Llm
    module Templates
      class CategorizeQuestion
        include Gitlab::Utils::StrongMemoize

        OUTPUT_TOKEN_LIMIT = 200

        SYSTEM_MESSAGE = Gitlab::Llm::Chain::Utils::Prompt.as_system(
          <<~PROMPT.chomp
            You are helpful assistant, ready to give as accurate answer as possible, in JSON format (i.e. starts with "{" and ends with "}").
          PROMPT
        )

        USER_MESSAGE = Gitlab::Llm::Chain::Utils::Prompt.as_user(
          <<~PROMPT.chomp
            Based on the information below (user input, categories, labels, language, %<previous_answer_prefix>s), classify user input's category, detailed_category, labels. There may be multiple labels. Don't provide clarification or explanation. Always return only a JSON hash, e.g.:
            <example>{"category": "Write, improve, or explain code", "detailed_category": "What are the potential security risks in this code?", "labels": ["contains_credentials", "contains_rejection_previous_answer_incorrect"], "language": "en"}</example>
            <example>{"category": "Documentation about GitLab", "detailed_category": "Documentation about GitLab", "labels": [], "language": "ja"}</example>

            %<previous_answer_section>s

            User input:
            <input>%<question>s</input>

            Categories:
            %<categories>s

            Labels:
            %<labels>s
          PROMPT
        )

        def initialize(messages, params = {})
          @messages = messages
          @params = params
        end

        def to_prompt
          previous_message = messages[-2]
          previous_answer = previous_message&.assistant? ? previous_message.content : nil

          if previous_answer
            previous_answer_prefix = "previous answer"
            previous_answer_section = "Previous answer:\n<answer>#{previous_answer}</answer>"
          else
            previous_answer_prefix = nil
            previous_answer_section = nil
          end

          variables = {
            question: params[:question],
            previous_answer_prefix: previous_answer_prefix,
            previous_answer_section: previous_answer_section,
            categories: ::Gitlab::Llm::AiGateway::Completions::CategorizeQuestion::LLM_MATCHING_CATEGORIES_XML,
            labels: ::Gitlab::Llm::AiGateway::Completions::CategorizeQuestion::LLM_MATCHING_LABELS_XML
          }

          {
            messages: Gitlab::Llm::Chain::Utils::Prompt.role_conversation(
              Gitlab::Llm::Chain::Utils::Prompt.format_conversation([USER_MESSAGE], variables)
            ),
            system: Gitlab::Llm::Chain::Utils::Prompt.no_role_text([SYSTEM_MESSAGE], {}),
            model: ::Gitlab::Llm::Anthropic::Client::CLAUDE_3_5_SONNET,
            max_tokens: OUTPUT_TOKEN_LIMIT
          }
        end

        private

        attr_reader :params, :messages
      end
    end
  end
end
