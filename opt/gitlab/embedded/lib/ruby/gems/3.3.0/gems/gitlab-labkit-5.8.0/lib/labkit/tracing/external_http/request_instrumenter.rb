# frozen_string_literal: true

module Labkit
  module Tracing
    module ExternalHttp
      # For more information on the payloads: lib/labkit/net_http_publisher.rb
      class RequestInstrumenter < Labkit::Tracing::AbstractInstrumenter
        def span_name(_payload)
          "external_http:request"
        end

        def tags(payload)
          # Duration is calculated by start and end time
          # Exception is already captured in lib/labkit/tracing/tracing_utils.rb
          tags = payload.slice(:method, :code, :host, :port, :path, :scheme, :proxy_host, :proxy_port)
          tags.transform_keys!(&:name)
          tags["component"] = "external_http"

          tags.compact!

          tags
        end
      end
    end
  end
end
