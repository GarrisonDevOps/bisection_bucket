# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      class StreamedResponseModifier < Gitlab::Llm::BaseResponseModifier
        def initialize(answer, options)
          @ai_response = answer
          @options = options
        end

        def response_body
          @ai_response = clean_prefix(@ai_response) if first_chunk?
          @ai_response
        end

        def errors
          []
        end

        private

        def first_chunk?
          @options && @options[:chunk_id] == 1
        end

        def clean_prefix(text)
          text&.lstrip&.delete_prefix(': ')&.delete_prefix('Answer: ')&.delete_prefix('Final Answer: ')
        end
      end
    end
  end
end
