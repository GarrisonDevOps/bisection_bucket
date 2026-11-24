# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path('generated', __dir__))

require 'grpc'

require_relative 'generated/secret_detection_pb'
require_relative 'generated/secret_detection_services_pb'

require_relative '../core'
require_relative '../../../../config/log'

# StreamEnumerator is used for Bi-directional streaming
# of requests by returning stream of responses.
class StreamEnumerator
  def initialize(requests, action)
    @requests = requests
    @request_action = action
  end

  def each_item
    return enum_for(:each_item) unless block_given?

    @requests.each do |req|
      yield @request_action.call(req)
    end
  end
end

module Gitlab
  module SecretDetection
    module GRPC
      class ScannerService < Scanner::Service
        include SDLogger
        include IntegratedErrorTracking

        # Maximum timeout value that can be given as the input. This guards
        # against the misuse of timeouts.
        MAX_ALLOWED_TIMEOUT_SECONDS = 600

        ERROR_MESSAGES = {
          invalid_payload_fields: "Payload should not contain empty `id` and `data` fields",
          exclusion_empty_value: "Exclusion value cannot be empty",
          exclusion_invalid_type: "Invalid exclusion type",
          invalid_timeout_range: "Timeout value should be > 0 and <= #{MAX_ALLOWED_TIMEOUT_SECONDS} seconds"
        }.freeze

        # Implementation for /Scan RPC method
        def scan(request, call)
          scan_request_action(request, call)
        end

        # Implementation for /ScanStream RPC method
        def scan_stream(requests, call)
          request_action = ->(r) { scan_request_action(r, call) }
          StreamEnumerator.new(requests, request_action).each_item
        end

        private

        def scan_request_action(request, call)
          if request.nil?
            logger.error(
              message: "FATAL: Secret Detection gRPC scan request is `nil`",
              deadline: call.deadline,
              cancelled: call.cancelled?
            )
            return Gitlab::SecretDetection::GRPC::ScanResponse.new(
              results: [],
              status: Gitlab::SecretDetection::GRPC::ScanResponse::Status::STATUS_INPUT_ERROR,
              applied_exclusions: []
            )
          end

          logger.info(message: "Secret Detection gRPC scan request received")

          validate_request(request)

          payloads = request.payloads.to_a
          exclusions = { raw_value: [], rule: [], path: [] }

          request.exclusions.each do |exclusion|
            case exclusion.exclusion_type
            when :EXCLUSION_TYPE_RAW_VALUE
              exclusions[:raw_value] << exclusion
            when :EXCLUSION_TYPE_RULE
              exclusions[:rule] << exclusion
            when :EXCLUSION_TYPE_PATH
              exclusions[:path] << exclusion
            else
              logger.warn("Unknown exclusion type #{exclusion.exclusion_type}")
            end
          end

          begin
            result = scanner.secrets_scan(
              payloads,
              exclusions:,
              tags: request.tags.to_a,
              timeout: request.timeout_secs,
              payload_timeout: request.payload_timeout_secs
            )
          rescue StandardError => e
            logger.error(message: "Failed to run the secret detection scan", exception: e.message)
            track_exception(e)
            raise ::GRPC::Unknown, e.message
          end

          findings = result.results&.map do |finding|
            Gitlab::SecretDetection::GRPC::ScanResponse::Finding.new(**finding.to_h)
          end

          Gitlab::SecretDetection::GRPC::ScanResponse.new(
            results: findings,
            status: result.status,
            applied_exclusions: result.applied_exclusions
          )
        end

        def scanner
          @scanner ||= Gitlab::SecretDetection::Core::Scanner.new(rules:, logger:)
        end

        def rules
          Gitlab::SecretDetection::Core::Ruleset.new.rules
        end

        # validates grpc request body
        def validate_request(request)
          # check for non-blank values and allowed types
          request.exclusions&.each do |exclusion|
            if exclusion.value.empty?
              raise ::GRPC::InvalidArgument.new(ERROR_MESSAGES[:exclusion_empty_value],
                { field: "exclusion.value" })
            end
          end

          unless valid_timeout_range?(request.timeout_secs)
            raise ::GRPC::InvalidArgument.new(ERROR_MESSAGES[:invalid_timeout_range],
              { field: "timeout_secs" })
          end

          unless valid_timeout_range?(request.payload_timeout_secs)
            raise ::GRPC::InvalidArgument.new(ERROR_MESSAGES[:invalid_timeout_range],
              { field: "payload_timeout_secs" })
          end

          # check for required payload fields
          request.payloads.to_a.each_with_index do |payload, index|
            if !payload.respond_to?(:id) || payload.id.empty?
              raise ::GRPC::InvalidArgument.new(
                ERROR_MESSAGES[:invalid_payload_fields],
                { field: "payloads[#{index}].id" }
              )
            end

            unless payload.respond_to?(:data) # rubocop:disable Style/Next
              raise ::GRPC::InvalidArgument.new(
                ERROR_MESSAGES[:invalid_payload_fields],
                { field: "payloads[#{index}].data" }
              )
            end
          end
        end

        # checks if the given timeout value is within range
        def valid_timeout_range?(timeout_value)
          timeout_value >= 0 && timeout_value <= MAX_ALLOWED_TIMEOUT_SECONDS
        end
      end
    end
  end
end
