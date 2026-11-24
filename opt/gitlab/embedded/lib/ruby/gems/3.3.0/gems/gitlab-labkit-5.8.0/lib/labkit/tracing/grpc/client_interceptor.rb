# frozen_string_literal: true

# Disable the UnusedMethodArgument linter, since we need to declare the kwargs
# in the methods, but we don't actually use them.
require "opentracing"
require "grpc"
require "singleton"

module Labkit
  module Tracing
    module GRPC
      # GRPCClientInterceptor is a client-side GRPC interceptor
      # for instrumenting GRPC calls with distributed tracing
      class ClientInterceptor < ::GRPC::ClientInterceptor
        include Singleton

        def request_response(request:, call:, method:, metadata:)
          wrap_with_tracing(method, "unary", metadata) { yield }
        end

        def client_streamer(requests:, call:, method:, metadata:)
          wrap_with_tracing(method, "client_stream", metadata) { yield }
        end

        def server_streamer(request:, call:, method:, metadata:)
          wrap_with_tracing(method, "server_stream", metadata) { yield }
        end

        def bidi_streamer(requests:, call:, method:, metadata:)
          wrap_with_tracing(method, "bidi_stream", metadata) { yield }
        end

        private

        def wrap_with_tracing(method, grpc_type, metadata)
          tags = { "component" => "grpc", "span.kind" => "client", "grpc.method" => method, "grpc.type" => grpc_type }

          TracingUtils.with_tracing(operation_name: "grpc:#{method}", tags: tags) do |span|
            TracingUtils.tracer.inject_context(span, metadata)

            yield
          end
        end
      end
    end
  end
end
