# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module ResponseModifiers
        class GitCommand < Base
          def response_body
            return if ai_response.blank?

            # Need to format the response like this since glab client expects
            # the response from API like this. Even if we change glab to parse
            # a different format, we also need to support older clients.
            {
              predictions: [
                {
                  candidates: [
                    {
                      content: ai_response
                    }
                  ]
                }
              ]
            }
          end
        end
      end
    end
  end
end
