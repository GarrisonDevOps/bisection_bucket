# frozen_string_literal: true

module AuditEvents
  module Streaming
    module Destinations
      class AmazonS3StreamDestination < BaseStreamDestination
        # SDK defaults (15s open, 60s read, 3 retries) let one stalled send hold a streaming
        # thread for minutes. Keep two retries: stalls are bursty and a fresh attempt usually
        # succeeds, and the job does not retry a failed send, so running out loses the event.
        BOUNDED_CLIENT_OPTIONS = {
          http_open_timeout: ::AuditEvents::HttpTimeoutConfig::DEFAULT[:open_timeout].to_i,
          http_read_timeout: ::AuditEvents::HttpTimeoutConfig::DEFAULT[:read_timeout].to_i,
          retry_limit: 2, # legacy retry mode
          max_attempts: 3 # standard and adaptive retry modes
        }.freeze

        def stream
          payload = request_body
          aws_s3_client.upload_object(filename(payload), bucket_name, payload, 'application/json')
        end

        # Breaking change for S3 (object layout); gated per-group behind
        # audit_event_streaming_via_nats. Key first_id disambiguates batches
        # that parallel partition drainers write within the same millisecond
        # to a shared instance destination, preventing a silent overwrite.
        # Delivery is at-least-once, so a redelivered batch produces a
        # near-duplicate object; consumers deduplicate by the per-event `id`.
        def stream_batch(event_bodies)
          raise ArgumentError, 'stream_batch requires a non-empty batch' if event_bodies.blank?

          payload = encode_body(event_bodies)
          aws_s3_client.upload_object(batch_filename(event_bodies), bucket_name, payload, 'application/json')
        end

        private

        def classify_error(error)
          case error
          when Seahorse::Client::NetworkingError then classify_networking_error(error)
          when Aws::Errors::ServiceError then classify_service_error(error)
          when Aws::Errors::MissingCredentialsError then :auth
          when Aws::Errors::InvalidRegionError then :invalid_config
          else super
          end
        end

        # The SDK wraps the socket-level exception; classify that one and treat
        # anything it cannot name as a connection failure.
        def classify_networking_error(error)
          inner = classify_error(error.original_error)

          inner == :internal_error ? :connection : inner
        end

        # S3 signals throttling as 503 SlowDown; the SDK's throttling? trait is
        # never set for S3 errors. PermanentRedirect means the bucket lives in
        # another region than the one configured.
        def classify_service_error(error)
          return :rate_limited if error.code == 'SlowDown'
          return :invalid_config if error.code == 'PermanentRedirect'
          # 4xx codes that a retry can fix (idle socket, conflicting operation, clock skew).
          return :timeout if error.code == 'RequestTimeout'
          return :server_error if %w[OperationAborted RequestTimeTooSkewed].include?(error.code)

          status_error_category(error.context&.http_response&.status_code) || :server_error
        end

        def batch_filename(event_bodies)
          "#{current_year_month_day}/#{time_in_ms}_#{event_bodies.first['id']}.json"
        end

        def aws_s3_client
          @aws_s3_client ||= Aws::S3Client.new(
            @destination.config["accessKeyXid"],
            @destination.secret_token,
            @destination.config["awsRegion"],
            **client_options
          )
        end

        def client_options
          return {} unless ::Feature.enabled?(:audit_event_streaming_destination_timeouts, feature_flag_actor)

          BOUNDED_CLIENT_OPTIONS
        end

        def bucket_name
          destination.config["bucketName"]
        end

        # Returns the name of the json file to be saved in the S3 bucket
        # Eg: Group/2023/09/update_approval_rules_887_1694441509820.json
        def filename(payload)
          # Remove audit_event['entity_type'] from below and only use Gitlab::Json.safe_parse(payload)['entity_type']
          # once feature flag is rolled out completely https://gitlab.com/gitlab-org/gitlab/-/issues/516895.
          # Check comment https://gitlab.com/gitlab-org/gitlab/-/issues/567249#note_2723093844
          parsed_payload = begin
            ::Gitlab::Json.safe_parse(payload)
          rescue JSON::ParserError
            nil
          end
          parsed_payload = nil unless parsed_payload.is_a?(Hash)

          audit_event_entity_type = audit_event['entity_type'] || parsed_payload&.dig('entity_type')

          entity_type = if audit_event_entity_type == 'Gitlab::Audit::InstanceScope'
                          'instance'
                        elsif audit_event_entity_type == 'Namespaces::UserNamespace'
                          'user'
                        elsif audit_event_entity_type.present?
                          # replace all non alpha numeric characters in audit_event['entity_type'] with underscore
                          audit_event_entity_type.downcase.gsub(/[^0-9A-Za-z]+/, '_')
                        else
                          'unspecified'
                        end

          "#{entity_type}/#{current_year_and_month}/#{event_type}_" \
            "#{parsed_payload&.dig('id')}_#{time_in_ms}.json"
        end

        def time_in_ms
          (Time.now.to_f * 1000).to_i
        end

        # @return [String] Eg: "2023/09"
        def current_year_and_month
          Date.current.strftime("%Y/%m")
        end

        def current_year_month_day
          Date.current.strftime("%Y/%m/%d")
        end
      end
    end
  end
end
