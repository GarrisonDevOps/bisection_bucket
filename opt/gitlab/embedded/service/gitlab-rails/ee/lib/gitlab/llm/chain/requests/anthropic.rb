# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Requests
        class Anthropic < Base
          attr_reader :ai_client

          PROMPT_SIZE = 30_000

          def initialize(user, unit_primitive:, tracking_context: {})
            @user = user
            @ai_client = ::Gitlab::Llm::Anthropic::Client.new(user,
              unit_primitive: unit_primitive, tracking_context: tracking_context)
          end

          # TODO: unit primitive param is temporarily added to provide parity with ai_gateway-related method
          def request(prompt, unit_primitive: nil) # rubocop: disable Lint/UnusedMethodArgument -- added to provide parity with ai_gateway-related method
            return unless prompt[:messages]

            ai_client.messages_stream(
              **prompt
            ) do |data|
              if data&.dig("error")
                log_error(message: "Streaming error",
                  event_name: 'error_response_received',
                  ai_component: 'abstraction_layer',
                  error: data&.dig("error", "type"))
              end

              content = data&.dig('delta', 'text').to_s
              yield content if block_given?
            end
          end

          private

          attr_reader :user
        end
      end
    end
  end
end
