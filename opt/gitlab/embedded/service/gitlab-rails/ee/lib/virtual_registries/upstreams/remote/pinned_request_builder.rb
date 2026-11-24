# frozen_string_literal: true

module VirtualRegistries
  module Upstreams
    module Remote
      # Builds a Typhoeus HEAD request whose target IP is pinned at validation
      # time, closing the DNS rebinding TOCTOU window that would otherwise exist
      # between UrlBlocker validation and libcurl's own DNS resolution.
      #
      # When DNS rebinding protection replaces the URI hostname with the
      # resolved IP, the resolved IP is pinned via CURLOPT_RESOLVE (Typhoeus's
      # `resolve:` option) while the original hostname is kept in the request
      # URL so TLS SNI and certificate hostname verification still work for
      # HTTPS targets.
      #
      # Returns nil when the URL is blocked by UrlBlocker; callers decide how
      # to treat a blocked request (skip, fail the upstream, etc.).
      class PinnedRequestBuilder
        def self.build(url, headers:, timeout:)
          result = validate_url(url)
          return unless result

          options = {
            headers: headers,
            method: :head,
            followlocation: false,
            timeout: timeout
          }

          if result.hostname
            port = result.uri.port || default_port_for(result.uri)
            options[:resolve] = build_resolve_slist(result.hostname, port, result.uri.hostname)

            request_uri = result.uri.dup
            request_uri.hostname = result.hostname
          else
            request_uri = result.uri
          end

          Typhoeus::Request.new(request_uri.to_s, **options)
        end

        # Typhoeus/Ethon do not auto-convert an Array<String> to a curl_slist
        # for CURLOPT_RESOLVE (unlike the HTTPHEADER option). Build the slist
        # ourselves and wrap it in an FFI::AutoPointer so libcurl frees it via
        # curl_slist_free_all once the Typhoeus::Request is garbage collected.
        def self.build_resolve_slist(host, port, ip)
          entry = "#{host}:#{port}:#{ip}"
          slist = Ethon::Curl.slist_append(nil, entry)
          FFI::AutoPointer.new(slist, Ethon::Curl.method(:slist_free_all))
        end

        # dns_rebind_protection stays hardcoded to true: the entire point of
        # PinnedRequestBuilder is closing the DNS rebinding TOCTOU window by
        # pinning the resolved IP via CURLOPT_RESOLVE. Disabling it would skip
        # the hostname-to-IP rewrite that the pinning relies on.
        #
        # allow_localhost, allow_local_network, and outbound_local_requests_allowlist
        # are threaded from instance settings so virtual registry fetches honor
        # the same outbound-local-requests configuration that Gitlab::HTTP
        # (and therefore Upstream#test and the model URL validator) already
        # honors. Without this, an upstream URL that passes save-time validation
        # and Test upstream can still be blocked at fetch time.
        def self.validate_url(url)
          Gitlab::HTTP_V2::UrlBlocker.validate_url_with_proxy!(
            url,
            schemes: %w[http https],
            allow_localhost: allow_local_requests?,
            allow_local_network: allow_local_requests?,
            dns_rebind_protection: true,
            outbound_local_requests_allowlist: Gitlab::CurrentSettings.outbound_local_requests_whitelist # rubocop:disable Naming/InclusiveLanguage -- existing application setting name
          )
        rescue Gitlab::HTTP_V2::UrlBlocker::BlockedUrlError
          nil
        end

        def self.allow_local_requests?
          Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services?
        end

        def self.default_port_for(uri)
          uri.scheme == 'https' ? 443 : 80
        end

        private_class_method :validate_url, :allow_local_requests?, :default_port_for, :build_resolve_slist
      end
    end
  end
end
