# frozen_string_literal: true

# Disable the UnusedMethodArgument linter, since we need to declare the kwargs
# in the methods, but we don't actually use them.

require "grpc"

module Labkit
  module Correlation
    module GRPC
      # ServerInterceptor is a server-side GRPC interceptor
      # for injecting GRPC calls with a correlation-id passed from
      # a GRPC client to the GRPC Ruby Service
      class ServerInterceptor < ::GRPC::ServerInterceptor
        include Labkit::Correlation::GRPC::GRPCCommon

        def request_response(request: nil, call: nil, method: nil)
          wrap_with_correlation_id(call) do
            yield
          end
        end

        def client_streamer(call: nil, method: nil)
          wrap_with_correlation_id(call) do
            yield
          end
        end

        def server_streamer(request: nil, call: nil, method: nil)
          wrap_with_correlation_id(call) do
            yield
          end
        end

        def bidi_streamer(requests: nil, call: nil, method: nil)
          wrap_with_correlation_id(call) do
            yield
          end
        end

        private

        def wrap_with_correlation_id(call, &block)
          correlation_id = call.metadata[CORRELATION_METADATA_KEY]
          correlation_id ||= Labkit::Correlation::CorrelationId.current_or_new_id

          Labkit::Correlation::CorrelationId.use_id(correlation_id, &block)
        end
      end
    end
  end
end
