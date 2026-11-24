# frozen_string_literal: true

module Gitlab
  module Llm
    module Evaluators
      class Base
        include Gitlab::Llm::Concerns::AiGatewayClientConcern

        def initialize(user:, tracking_context: {}, options: {})
          @user = user
          @tracking_context = tracking_context
          @options = options
        end

        def execute
          perform_ai_gateway_request!(user:, tracking_context:)
        end

        private

        attr_reader :user, :tracking_context, :options

        # @return [Symbol] Must be overridden by subclasses to specify the UP name.
        def unit_primitive_name
          raise NotImplementedError
        end

        # @return [Hash<Symbol, String>] The model metadata to pass on to AI Gateway.
        def model_metadata(user)
          raise NotImplementedError
        end

        # @return [Symbol] The name of the prompt to be used by the AI Gateway.
        def prompt_name
          raise NotImplementedError
        end

        # @return [String] The version of the prompt to be used by the AI Gateway.
        def prompt_version
          raise NotImplementedError
        end

        # @return [Hash] The inputs sent over to the AI Gateway.
        def inputs
          raise NotImplementedError
        end
      end
    end
  end
end
