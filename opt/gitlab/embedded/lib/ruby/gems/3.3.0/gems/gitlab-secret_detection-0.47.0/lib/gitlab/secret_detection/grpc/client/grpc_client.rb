# frozen_string_literal: true

require 'grpc'
require_relative '../../grpc/scanner_service'
require_relative '../../core/response'
require_relative '../../core/status'
require_relative '../../utils'
require_relative './stream_request_enumerator'

module Gitlab
  module SecretDetection
    module GRPC
      class Client
        include SecretDetection::Utils::StrongMemoize
        include SDLogger

        # Time to wait for the response from the service
        REQUEST_TIMEOUT_SECONDS = 10 # 10 seconds

        # Total payload size limit allowed per scan request
        MAX_PAYLOAD_SIZE_PER_REQUEST = 4_000_000 # 3.8MiB (0.2MiB buffer for other request props)

        def initialize(host, secure: false, compression: true, logger: nil)
          @host = host
          @secure = secure
          @compression = compression
          @logger = logger.nil? ? LOGGER : logger
        end

        # Triggers Secret Detection service's `/Scan` gRPC endpoint. To keep it consistent with SDS gem interface,
        # this method transforms the gRPC response to +Gitlab::SecretDetection::Core::Response+.
        # Furthermore, any errors that are raised by the service will be translated to
        # +Gitlab::SecretDetection::Core::Response+ type by assiging a appropriate +status+ value to it.
        def run_scan(request:, auth_token:, extra_headers: {})
          with_rescued_errors do
            payload_size = calculate_payload_size(request)
            if payload_size >= MAX_PAYLOAD_SIZE_PER_REQUEST
              @logger.info(
                message: "Skipping to send Scan Request to Secret Detection server due to request size overlimit",
                payload_size:
              )

              next Gitlab::SecretDetection::GRPC::ScanResponse.new(
                results: [],
                status: SecretDetection::Core::Status::INPUT_ERROR,
                applied_exclusions: []
              )
            end

            grpc_response = stub.scan(
              request,
              metadata: build_metadata(auth_token, extra_headers),
              deadline: request_deadline
            )

            grpc_response
          end
        end

        # Triggers Secret Detection service's `/ScanStream` gRPC endpoint.
        #
        # To keep it consistent with SDS gem interface, this method transforms the gRPC response to
        # +Gitlab::SecretDetection::Core::Response+ type. Furthermore, any errors that are raised by the service will be
        # translated to +Gitlab::SecretDetection::Core::Response+ type by assiging a appropriate +status+ value to it.
        #
        # Note: If one of the stream requests result in an error, the stream will end immediately without processing the
        # remaining requests.
        def run_scan_stream(requests:, auth_token:, extra_headers: {})
          request_stream = Gitlab::SecretDetection::GRPC::StreamRequestEnumerator.new(requests)
          results = []
          with_rescued_errors do
            has_oversized_request = requests.any? do |request|
              payload_size = calculate_payload_size(request)
              payload_size >= MAX_PAYLOAD_SIZE_PER_REQUEST
            end

            if has_oversized_request
              @logger.info("Skipping to send Scan Request to Secret Detection server due to request size overlimit")
              response = Gitlab::SecretDetection::GRPC::ScanResponse.new(
                status: SecretDetection::Core::Status::INPUT_ERROR
              )
              next (block_given? ? response : [response])
            end

            stub.scan_stream(
              request_stream.each_item,
              metadata: build_metadata(auth_token, extra_headers),
              deadline: request_deadline
            ).each do |grpc_response|
              if block_given?
                yield grpc_response
              else
                results << grpc_response
              end
            end
            results
          end
        end

        private

        attr_reader :secure, :host, :compression

        def stub
          Gitlab::SecretDetection::GRPC::Scanner::Stub.new(
            host,
            channel_credentials,
            channel_args:
          )
        end

        strong_memoize_attr :stub

        def channel_args
          default_options = {
            'grpc.keepalive_permit_without_calls' => 1,
            'grpc.keepalive_time_ms' => 30000, # 30 seconds
            'grpc.keepalive_timeout_ms' => 10000 # 10 seconds timeout for keepalive response
          }

          compression_options = ::GRPC::Core::CompressionOptions
                                  .new(default_algorithm: :gzip)
                                  .to_channel_arg_hash

          default_options.merge!(compression_options) if compression

          default_options.freeze
        end

        def channel_credentials
          return :this_channel_is_insecure unless secure

          certs = Gitlab::SecretDetection::Utils::X509::Certificate.ca_certs_bundle

          ::GRPC::Core::ChannelCredentials.new(certs)
        end

        def build_metadata(token, extra_headers = {})
          { 'x-sd-auth' => token }.merge!(extra_headers).freeze
        end

        def request_deadline
          Time.now + REQUEST_TIMEOUT_SECONDS
        end

        def with_rescued_errors
          yield
        rescue ::GRPC::Unauthenticated
          SecretDetection::Core::Response.new(status: SecretDetection::Core::Status::AUTH_ERROR)
        rescue ::GRPC::InvalidArgument => e
          SecretDetection::Core::Response.new(
            status: SecretDetection::Core::Status::INPUT_ERROR,
            results: nil,
            metadata: { message: e.details, **e.metadata }
          )
        rescue ::GRPC::ResourceExhausted => e
          @logger.error(message: "Secret Detection Server resource exhausted: #{e.details}", **e.metadata)
          SecretDetection::Core::Response.new(
            status: SecretDetection::Core::Status::SCAN_ERROR,
            metadata: { message: e.details, **e.metadata }
          )
        rescue ::GRPC::Unknown, ::GRPC::BadStatus => e
          SecretDetection::Core::Response.new(
            status: SecretDetection::Core::Status::SCAN_ERROR,
            results: nil,
            metadata: { message: e.details, **e.metadata }
          )
        end

        def calculate_payload_size(request)
          request&.payloads&.reduce(0) { |total, p| total + p.data.size + p.id.size }
        end
      end
    end
  end
end
