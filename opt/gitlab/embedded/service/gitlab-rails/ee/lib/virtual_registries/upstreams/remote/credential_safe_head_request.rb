# frozen_string_literal: true

module VirtualRegistries
  module Upstreams
    module Remote
      # Performs an HTTP HEAD against a remote upstream, following redirects
      # manually so that credential headers are dropped on cross-host hops.
      #
      # `Gitlab::HTTP` (HTTParty) can follow redirects on its own, but it replays
      # the caller-supplied Authorization header on every hop, including cross-host
      # ones, which leaks an upstream's credentials to the redirect target (for
      # example a pre-signed object-storage URL). We therefore follow redirects
      # ourselves and run each hop through CrossHostCredentialFilter.
      #
      # We roll our own loop rather than reuse Faraday's `clear_authorization_header`
      # (as ContainerRegistry::Client does) because we need the SSRF check, the
      # same-host/subdomain rule, and Cookie stripping on every hop, none of which
      # that option provides, and the HTTParty backend can't rewrite headers per hop.
      #
      # Every hop is re-issued through `Gitlab::HTTP`, so SSRF validation runs on each
      # redirect target. This relies on the instance's `dns_rebinding_protection_enabled`
      # setting; unlike the RedirectHandler/Typhoeus path (which pins the resolved IP via
      # PinnedRequestBuilder regardless), this path is weaker against DNS rebinding when
      # that setting is disabled.
      class CredentialSafeHeadRequest
        include RedirectRules

        def self.head(url:, headers:, timeout:)
          new(url: url, headers: headers, timeout: timeout).head
        end

        def initialize(url:, headers:, timeout:)
          @url = url
          @headers = headers
          @timeout = timeout
        end

        def head
          current_url = url
          current_headers = headers
          response = nil

          (MAX_REDIRECTS + 1).times do
            # `timeout` is per hop (up to (MAX_REDIRECTS + 1) * timeout for the chain),
            # preserving the old follow_redirects: true behavior and matching the async
            # RedirectHandler path.
            response = ::Gitlab::HTTP.head(
              current_url,
              headers: current_headers,
              follow_redirects: false,
              timeout: timeout
            )

            return response unless redirect?(response)

            target_url = redirect_target(response, current_url)
            return response unless target_url

            current_headers = CrossHostCredentialFilter.filter_headers(
              current_headers, source_url: current_url, target_url: target_url
            )
            current_url = target_url
          end

          raise ::Gitlab::HTTP::RedirectionTooDeep
        end

        private

        attr_reader :url, :headers, :timeout

        # Reads the last Location value and resolves it against the current URL, so
        # relative redirects keep the same host (and therefore keep their
        # credentials). A repeated header comma-joins under `[]`, so we use
        # get_fields to take the last value and match RedirectHandler's policy.
        # This differs from the RedirectHandler/Typhoeus path, which does not
        # resolve relative Locations.
        def redirect_target(response, source_url)
          location = response.headers.get_fields('location')&.last
          return unless location.is_a?(String) && location.present?

          target = Addressable::URI.join(source_url, location).to_s
          URI.parse(target)
          target
        rescue Addressable::URI::InvalidURIError, URI::InvalidURIError, ArgumentError
          nil
        end
      end
    end
  end
end
