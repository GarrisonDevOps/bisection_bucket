# frozen_string_literal: true

# Disable the UnusedMethodArgument linter, since we need to declare the kwargs
# in the methods, but we don't actually use them.

require "opentracing"
require "grpc"

module Labkit
  module Tracing
    module GRPC
      # GRPCServerInterceptor is a server-side GRPC interceptor
      # for instrumenting GRPC calls with distributed tracing
      # in a GRPC Ruby server
      class ServerInterceptor < ::GRPC::ServerInterceptor
        include Labkit::Correlation::GRPC::GRPCCommon

        def request_response(request: nil, call: nil, method: nil)
          wrap_with_tracing(call, method, "unary") do
            yield
          end
        end

        def client_streamer(call: nil, method: nil)
          wrap_with_tracing(call, method, "client_stream") do
            yield
          end
        end

        def server_streamer(request: nil, call: nil, method: nil)
          wrap_with_tracing(call, method, "server_stream") do
            yield
          end
        end

        def bidi_streamer(requests: nil, call: nil, method: nil)
          wrap_with_tracing(call, method, "bidi_stream") do
            yield
          end
        end

        private

        def wrap_with_tracing(call, method, grpc_type)
          context = TracingUtils.tracer.extract_context(call.metadata)
          method_name = "/#{rpc_split(method).join("/")}"
          tags = {
            "component" => "grpc",
            "span.kind" => "server",
            "grpc.method" => method_name,
            "grpc.type" => grpc_type
          }

          TracingUtils.with_tracing(operation_name: "grpc:#{method_name}", child_of: context, tags: tags) do |_span|
            yield
          end
        end
      end
    end
  end
end
