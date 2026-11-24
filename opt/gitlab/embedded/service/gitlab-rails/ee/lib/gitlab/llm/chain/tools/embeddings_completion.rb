# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        class EmbeddingsCompletion
          include ::Gitlab::Loggable
          include Langsmith::RunHelpers
          include ::Gitlab::Llm::Concerns::Logger

          def initialize(current_user:, question:, search_documents:, tracking_context: {})
            @current_user = current_user
            @question = question
            @search_documents = search_documents
            @correlation_id = Labkit::Correlation::CorrelationId.current_id
            @tracking_context = tracking_context
          end

          def execute(&)
            get_completions_ai_gateway(search_documents, &)
          end

          private

          attr_reader :current_user, :question, :search_documents, :correlation_id, :tracking_context

          def ai_gateway_request
            @ai_gateway_request ||= ::Gitlab::Llm::Chain::Requests::AiGateway.new(current_user,
              unit_primitive_name: :duo_classic_chat,
              tracking_context: tracking_context)
          end

          def get_completions_ai_gateway(search_documents)
            final_prompt = Gitlab::Llm::Anthropic::Templates::TanukiBot
              .final_prompt(question: question, documents: search_documents)

            final_prompt_result = ai_gateway_request.request(
              {
                prompt: final_prompt[:prompt],
                options: final_prompt[:options]
              },
              unit_primitive: :documentation_search
            ) do |data|
              yield data if block_given?
            end

            log_conditional_info(current_user,
              message: "Got Final Result for documentation question content",
              event_name: 'response_received',
              ai_component: 'duo_chat',
              prompt: final_prompt[:prompt],
              response_from_llm: final_prompt_result)

            Gitlab::Llm::Anthropic::ResponseModifiers::TanukiBot.new(
              { completion: final_prompt_result }.to_json,
              current_user,
              search_documents: search_documents
            )

          rescue Gitlab::Llm::AiGateway::Client::ConnectionError => error
            Gitlab::ErrorTracking.track_exception(error)

            log_error(message: "Streaming error",
              event_name: 'error_response_received',
              ai_component: 'duo_chat',
              error: error.message)
          end
        end
      end
    end
  end
end
