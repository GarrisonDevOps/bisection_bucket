# frozen_string_literal: true

module VirtualRegistries
  module Upstreams
    module Remote
      class CheckService < ::VirtualRegistries::Upstreams::CheckBaseService
        MAX_CONCURRENCY = 3
        NETWORK_TIMEOUT = 5

        def initialize(upstreams:, params: {})
          super

          @hydra = Typhoeus::Hydra.new(max_concurrency: MAX_CONCURRENCY)
        end

        private

        attr_reader :hydra

        def check
          configure_hydra
          hydra.run

          return ERRORS[:file_not_found_on_upstreams] unless first_successful_index

          ServiceResponse.success(payload: { upstream: upstreams[first_successful_index] })
        end

        def configure_hydra
          upstreams.each_with_index do |upstream, index|
            headers = upstream.headers(path)
            url = upstream.url_for(path)
            redirect_handler = RedirectHandler.new(headers: headers, timeout: NETWORK_TIMEOUT, url: url)

            request = PinnedRequestBuilder.build(
              url,
              headers: headers,
              timeout: NETWORK_TIMEOUT
            )

            if request
              request.on_complete { |response| handle_response(response, index, redirect_handler) }
              hydra.queue(request)
            else
              # Upstream URL was blocked by UrlBlocker at request time (e.g. DNS
              # rebinding replacement resolved to an internal IP). Treat as a
              # failed upstream rather than dispatching an unvalidated request.
              results[index] = false
            end
          end
        end

        def handle_response(response, index, redirect_handler)
          if redirect_handler.redirect?(response)
            handle_redirect(response, index, redirect_handler)
          else
            record_result(response, index)
          end
        end

        def handle_redirect(response, index, redirect_handler)
          follow_request = redirect_handler.build_follow_request(response) do |follow_response, next_handler|
            handle_response(follow_response, index, next_handler)
          end

          if follow_request
            hydra.queue(follow_request)
          else
            # Redirect was blocked (invalid URL or max redirects exceeded)
            results[index] = false
            hydra.abort if first_successful_index
          end
        end

        def record_result(response, index)
          # Given that each url is checked in parallel, the order which we receive the
          # results are not guaranteed. Thus, we need to first record the result for
          # this index and then check the results array to know if we are in a
          # success state or not. If that's the case, we need to get which index
          # contains the first true value.
          results[index] = response.success?
          hydra.abort if first_successful_index
        end
      end
    end
  end
end
