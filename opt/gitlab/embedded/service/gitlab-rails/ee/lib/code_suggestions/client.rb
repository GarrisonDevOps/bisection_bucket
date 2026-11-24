# frozen_string_literal: true

module CodeSuggestions
  # This class represents the client making a code suggestion request to the GitLab Rails API
  class Client
    SUPPORTS_SSE_STREAMING_HEADER = 'X-Supports-Sse-Streaming'

    def initialize(headers)
      @headers = headers
    end

    def supports_sse_streaming?
      true?(headers[SUPPORTS_SSE_STREAMING_HEADER])
    end

    private

    attr_reader :headers

    def true?(value)
      value = value.to_s.downcase
      value == 'true' || value == '1'
    end
  end
end
