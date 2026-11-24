# frozen_string_literal: true

module CodeSuggestions
  module Prompts
    module CodeCompletion
      class AiGatewayCodeEditorCompletion < CodeSuggestions::Prompts::Base
        PROMPT_COMPONENT_TYPE = 'code_editor_completion'
        CODE_CONTEXT_COMPONENT_TYPE = 'code_context'
        MAX_CONTENT_CHARS = 100_000

        def request_params
          {
            prompt_components: [completion_component, *code_context_components],
            **model_metadata
          }
        end

        private

        def completion_component
          {
            type: PROMPT_COMPONENT_TYPE,
            payload: {
              file_name: file_name,
              content_above_cursor: content_above_cursor.to_s.last(MAX_CONTENT_CHARS),
              content_below_cursor: content_below_cursor.to_s.first(MAX_CONTENT_CHARS),
              language_identifier: language.name,
              stream: params.fetch(:stream, false)
            }
          }
        end

        def code_context_components
          Array(params[:context]).map do |context|
            {
              type: CODE_CONTEXT_COMPONENT_TYPE,
              payload: { type: context[:type], name: context[:name], content: context[:content] }
            }
          end
        end

        def model_metadata
          metadata = ::Gitlab::Llm::AiGateway::ModelMetadata.new(feature_setting: feature_setting).to_params

          return {} unless metadata && use_model_metadata?

          { model_metadata: metadata }
        end

        def use_model_metadata?
          ::Ai::AmazonQ.connected? ||
            feature_setting&.self_hosted? ||
            feature_setting&.try(:offered_model_ref).present?
        end
      end
    end
  end
end
