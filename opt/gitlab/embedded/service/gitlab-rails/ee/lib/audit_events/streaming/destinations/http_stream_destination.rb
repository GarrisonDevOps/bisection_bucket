# frozen_string_literal: true

module AuditEvents
  module Streaming
    module Destinations
      class HttpStreamDestination < BaseStreamDestination
        STREAMING_TOKEN_HEADER_KEY = "X-Gitlab-Event-Streaming-Token"

        def stream
          response = Gitlab::HTTP.post(
            destination.config["url"],
            body: request_body,
            headers: build_headers,
            **::AuditEvents::HttpTimeoutConfig::DEFAULT
          )

          ensure_success(response)
        end

        # Breaking change for HTTP (body is now a JSON array); gated per-group
        # behind audit_event_streaming_via_nats. The per-request
        # X-Gitlab-Audit-Event-Type header is dropped because a mixed batch has
        # no single type; each element self-describes via `event_type`.
        def stream_batch(event_bodies)
          response = Gitlab::HTTP.post(
            destination.config["url"],
            body: encode_body(event_bodies),
            headers: build_headers,
            **::AuditEvents::HttpTimeoutConfig::DEFAULT
          )

          ensure_success(response)
        end

        private

        def build_headers
          headers = @destination.headers_hash
          headers[EVENT_TYPE_HEADER_KEY] = @event_type if @event_type.present?
          headers
        end
      end
    end
  end
end
