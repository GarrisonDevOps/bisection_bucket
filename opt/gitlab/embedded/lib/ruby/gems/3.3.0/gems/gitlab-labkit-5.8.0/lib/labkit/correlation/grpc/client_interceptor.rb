# frozen_string_literal: true

# Disable the UnusedMethodArgument linter, since we need to declare the kwargs
# in the methods, but we don't actually use them.
require "grpc"
require "singleton"

module Labkit
  module Correlation
    module GRPC
      # ClientInterceptor is used to inject the correlation_id into the metadata
      # or a GRPC call for onward propagation to the server
      class ClientInterceptor < ::GRPC::ClientInterceptor
        include Labkit::Correlation::GRPC::GRPCCommon
        include Singleton

        def request_response(request:, call:, method:, metadata:)
          inject_correlation_id_into_metadata(metadata)

          yield
        end

        def client_streamer(requests:, call:, method:, metadata:)
          inject_correlation_id_into_metadata(metadata)

          yield
        end

        def server_streamer(request:, call:, method:, metadata:)
          inject_correlation_id_into_metadata(metadata)

          yield
        end

        def bidi_streamer(requests:, call:, method:, metadata:)
          inject_correlation_id_into_metadata(metadata)

          yield
        end

        private

        def inject_correlation_id_into_metadata(metadata, &block)
          metadata[CORRELATION_METADATA_KEY] = Labkit::Correlation::CorrelationId.current_id if Labkit::Correlation::CorrelationId.current_id
        end
      end
    end
  end
end
