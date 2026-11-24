# frozen_string_literal: true

module CodeSuggestions
  module Tasks
    class CodeGeneration < CodeSuggestions::Tasks::Base
      extend ::Gitlab::Utils::Override
      include Gitlab::Utils::StrongMemoize

      override :endpoint
      def endpoint
        "#{base_url}/v4/code/suggestions"
      end

      private

      override :passthrough_params
      def passthrough_params
        {}
      end

      def prompt_request_params
        prompt.request_params
      end

      def model_details
        @model_details ||= CodeSuggestions::ModelDetails::Base.new(
          current_user: current_user,
          feature_setting_name: :code_generations,
          unit_primitive_name: :generate_code,
          root_namespace: params[:project]&.root_ancestor
        )
      end

      def prompt
        CodeSuggestions::Prompts::CodeGeneration::AiGatewayMessages.new(params, current_user, feature_setting)
      end

      strong_memoize_attr :prompt
    end
  end
end
