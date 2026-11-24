# frozen_string_literal: true

module Gitlab
  module Llm
    module Embeddings
      class Response
        attr_reader :http_response

        def initialize(http_response)
          @http_response = http_response # HTTParty::Response
        end

        def success?
          http_response&.success?
        end

        def status_code
          http_response.code
        end

        def parsed_response
          http_response&.parsed_response
        end

        def error
          @error ||= error_message
        end

        def embeddings
          return unless success?

          (parsed_response['predictions'] || []).pluck('embedding') # rubocop: disable CodeReuse/ActiveRecord -- not an ActiveRecord model
        end

        private

        def error_message
          return if success?

          return 'embeddings generation had no response' if http_response.nil?

          err = parsed_response&.dig('detail') || http_response.body.to_s
          "could not generate embeddings: #{err}"
        end
      end
    end
  end
end
