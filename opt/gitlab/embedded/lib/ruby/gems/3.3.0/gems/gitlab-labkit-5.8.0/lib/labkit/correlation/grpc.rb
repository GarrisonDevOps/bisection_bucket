# frozen_string_literal: true

module Labkit
  module Correlation
    # The GRPC module contains functionality for instrumenting GRPC calls
    module GRPC
      autoload :ClientInterceptor, "labkit/correlation/grpc/client_interceptor"
      autoload :GRPCCommon, "labkit/correlation/grpc/grpc_common"
      autoload :ServerInterceptor, "labkit/correlation/grpc/server_interceptor"
    end
  end
end
