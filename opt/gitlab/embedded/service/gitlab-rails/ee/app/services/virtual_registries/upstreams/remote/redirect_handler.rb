# frozen_string_literal: true

module VirtualRegistries
  module Upstreams
    module Remote
      class RedirectHandler
        include RedirectRules

        def initialize(headers:, timeout:, url:, redirect_count: 0)
          @headers = headers
          @timeout = timeout
          @url = url
          @redirect_count = redirect_count
        end

        def build_follow_request(response)
          return if max_redirects_exceeded?

          target_url = redirect_url(response)
          return unless target_url

          follow_headers = CrossHostCredentialFilter.filter_headers(headers, source_url: url, target_url: target_url)

          request = PinnedRequestBuilder.build(target_url, headers: follow_headers, timeout: timeout)
          return unless request

          next_handler = self.class.new(
            headers: follow_headers,
            timeout: timeout,
            url: target_url,
            redirect_count: redirect_count + 1
          )

          request.on_complete do |follow_response|
            yield(follow_response, next_handler)
          end

          request
        end

        private

        attr_reader :headers, :timeout, :url, :redirect_count

        # Reads Location from Typhoeus's raw response headers. Lookup is
        # case-insensitive (Typhoeus::Response::Header folds case, so an HTTP/2
        # lower-cased key still matches) and a repeated header comes back as an
        # Array, so we take the last value; anything that isn't a present String
        # is rejected since this is an untrusted upstream header. Unlike
        # CredentialSafeHeadRequest (the Gitlab::HTTP path), we don't resolve
        # relative Locations here; a relative redirect is treated as cross-host
        # and dropped.
        def redirect_url(response)
          response_headers = response.headers
          return unless response_headers

          location = Array.wrap(response_headers['Location']).last
          location if location.is_a?(String) && location.present?
        end

        def max_redirects_exceeded?
          redirect_count >= MAX_REDIRECTS
        end
      end
    end
  end
end
