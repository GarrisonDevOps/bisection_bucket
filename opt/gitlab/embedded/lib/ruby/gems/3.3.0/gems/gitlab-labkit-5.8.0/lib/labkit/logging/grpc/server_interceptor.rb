# frozen_string_literal: true

require "active_support/time_with_zone"
require "active_support/values/time_zone"
require "grpc"
require "json"

module Labkit
  module Logging
    module GRPC
      class ServerInterceptor < ::GRPC::ServerInterceptor
        include Labkit::Correlation::GRPC::GRPCCommon

        CODE_STRINGS = {
          ::GRPC::Core::StatusCodes::OK => "OK",
          ::GRPC::Core::StatusCodes::CANCELLED => "Canceled",
          ::GRPC::Core::StatusCodes::UNKNOWN => "Unknown",
          ::GRPC::Core::StatusCodes::INVALID_ARGUMENT => "InvalidArgument",
          ::GRPC::Core::StatusCodes::DEADLINE_EXCEEDED => "DeadlineExceeded",
          ::GRPC::Core::StatusCodes::NOT_FOUND => "NotFound",
          ::GRPC::Core::StatusCodes::ALREADY_EXISTS => "AlreadyExists",
          ::GRPC::Core::StatusCodes::PERMISSION_DENIED => "PermissionDenied",
          ::GRPC::Core::StatusCodes::RESOURCE_EXHAUSTED => "ResourceExhausted",
          ::GRPC::Core::StatusCodes::FAILED_PRECONDITION => "FailedPrecondition",
          ::GRPC::Core::StatusCodes::ABORTED => "Aborted",
          ::GRPC::Core::StatusCodes::OUT_OF_RANGE => "OutOfRange",
          ::GRPC::Core::StatusCodes::UNIMPLEMENTED => "Unimplemented",
          ::GRPC::Core::StatusCodes::INTERNAL => "Internal",
          ::GRPC::Core::StatusCodes::UNAVAILABLE => "Unavailable",
          ::GRPC::Core::StatusCodes::DATA_LOSS => "DataLoss",
          ::GRPC::Core::StatusCodes::UNAUTHENTICATED => "Unauthenticated",
        }.freeze

        def initialize(log_file, default_tags)
          @log_file = log_file
          @log_file.sync = true
          @default_tags = default_tags

          super()
        end

        def request_response(request: nil, call: nil, method: nil)
          log_request(method, call) { yield }
        end

        def server_streamer(request: nil, call: nil, method: nil)
          log_request(method, call) { yield }
        end

        def client_streamer(call: nil, method: nil)
          log_request(method, call) { yield }
        end

        def bidi_streamer(requests: nil, call: nil, method: nil)
          log_request(method, call) { yield }
        end

        private

        def log_request(method, _call)
          start = Time.now
          code = ::GRPC::Core::StatusCodes::OK

          yield
        rescue StandardError => ex
          code = ex.is_a?(::GRPC::BadStatus) ? ex.code : ::GRPC::Core::StatusCodes::UNKNOWN

          raise
        ensure
          service_name, method_name = rpc_split(method)
          message = @default_tags.merge(
            'grpc.start_time': start.utc.rfc3339,
            'grpc.time_ms': ((Time.now - start) * 1000.0).truncate(3),
            'grpc.code': CODE_STRINGS.fetch(code, code.to_s),
            'grpc.method': method_name,
            'grpc.service': service_name,
            pid: Process.pid,
            correlation_id: Labkit::Correlation::CorrelationId.current_id.to_s,
            time: Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S.%LZ"),
          )

          if ex
            message["exception"] = ex.message
            message["exception_backtrace"] = ex.backtrace[0..5] if ex.backtrace
          end

          @log_file.puts(JSON.dump(message))
        end
      end
    end
  end
end
