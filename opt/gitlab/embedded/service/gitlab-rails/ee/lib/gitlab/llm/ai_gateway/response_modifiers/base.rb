# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module ResponseModifiers
        class Base < Gitlab::Llm::BaseResponseModifier
          extend ::Gitlab::Utils::Override

          def initialize(ai_response)
            @ai_response = ai_response
          end

          override :response_body
          def response_body
            ai_response
          end

          override :errors
          def errors
            # On success, the response is just a plain JSON string
            @errors ||= ai_response.is_a?(String) ? [] : error_from_response
          end

          private

          def error_from_response
            return if ai_response.nil?

            detail = ai_response['detail']

            [detail.is_a?(String) ? detail : detail&.dig(0, 'msg')].compact
          end
        end
      end
    end
  end
end
