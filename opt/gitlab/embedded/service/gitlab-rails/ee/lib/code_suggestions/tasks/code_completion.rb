# frozen_string_literal: true

module CodeSuggestions
  module Tasks
    class CodeCompletion < Base
      extend ::Gitlab::Utils::Override

      delegate :remap_model_metadata, to: :model_details

      override :endpoint
      def endpoint
        "#{base_url}/v4/code/suggestions"
      end

      private

      override :passthrough_params
      def passthrough_params
        {}
      end

      override :prompt_request_params
      def prompt_request_params
        request_params = prompt.request_params
        return request_params unless request_params[:model_metadata]

        request_params.merge(model_metadata: remap_model_metadata(request_params[:model_metadata]))
      end

      override :model_details
      def model_details
        @model_details ||= CodeSuggestions::ModelDetails::CodeCompletion.new(
          current_user: current_user,
          root_namespace: params[:project]&.root_namespace
        )
      end

      def prompt
        CodeSuggestions::Prompts::CodeCompletion::AiGatewayCodeEditorCompletion.new(
          params,
          current_user,
          feature_setting
        )
      end
    end
  end
end
