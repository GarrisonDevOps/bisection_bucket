# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class Base < Llm::Completions::Base
          include Gitlab::Llm::Concerns::AiGatewayClientConcern

          DEFAULT_ERROR = 'An unexpected error has occurred.'
          RESPONSE_MODIFIER = ResponseModifiers::Base

          def execute
            return unless valid?

            response = request!
            response_modifier = self.class::RESPONSE_MODIFIER.new(post_process(response))

            ::Gitlab::Llm::GraphqlSubscriptionResponseService.new(
              user, resource, response_modifier, options: response_options
            ).execute
          end

          private

          # Can be overwritten by child classes to perform additional validations
          def valid?
            true
          end

          # Successful gateway responses are usually Strings but are not guaranteed to be. Request failures use a
          # Hash with a String 'detail', so subclasses must validate response shapes before parsing them.
          def post_process(response)
            response
          end

          def request!
            response = perform_ai_gateway_request!(user: user, tracking_context: tracking_context)

            return response if response.present?

            { 'detail' => DEFAULT_ERROR }
          rescue ArgumentError => e
            { 'detail' => e.message }
          rescue StandardError => e
            Gitlab::ErrorTracking.track_exception(e, ai_action: prompt_message.ai_action)

            { 'detail' => DEFAULT_ERROR }
          end

          def unit_primitive_name
            prompt_message.ai_action.to_sym
          end

          def prompt_name
            prompt_message.ai_action
          end
        end
      end
    end
  end
end
