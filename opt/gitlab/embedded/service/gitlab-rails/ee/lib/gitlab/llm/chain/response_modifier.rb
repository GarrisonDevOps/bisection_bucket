# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      class ResponseModifier < Gitlab::Llm::BaseResponseModifier
        attr_reader :ai_response

        def initialize(answer)
          @ai_response = answer
        end

        def response_body
          @response_body ||= ai_response.content
        end

        def extras
          @extras ||= ai_response.extras
        end

        def errors
          @errors ||= ai_response.status == :error ? [error_message] : []
        end

        private

        def error_message
          message = ai_response.content
          if ai_response.error_code.present?
            url = "#{Gitlab.doc_url}/ee/user/gitlab_duo_chat/troubleshooting.html" \
              "#error-#{ai_response.error_code.downcase}"

            message += " #{_('Error code')}: [#{ai_response.error_code}](#{url})"
          end

          message
        end
      end
    end
  end
end
