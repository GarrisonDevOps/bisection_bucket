# frozen_string_literal: true

module Labkit
  module Correlation
    module GRPC
      # This module is shared between the client and server interceptor middlewares.
      # It is not part of the public API
      module GRPCCommon
        CORRELATION_METADATA_KEY = "x-gitlab-correlation-id"

        def rpc_split(method)
          owner = method.owner
          method_name, = owner.rpc_descs.find do |k, _|
            ::GRPC::GenericService.underscore(k.to_s) == method.name.to_s
          end
          method_name ||= "(unknown)"

          [owner.service_name, method_name]
        end
      end
    end
  end
end
