# frozen_string_literal: true

module Labkit
  module Tracing
    # The GRPC module contains functionality for instrumenting GRPC calls
    module GRPC
      autoload :ClientInterceptor, "labkit/tracing/grpc/client_interceptor"
      autoload :ServerInterceptor, "labkit/tracing/grpc/server_interceptor"
    end
  end
end
