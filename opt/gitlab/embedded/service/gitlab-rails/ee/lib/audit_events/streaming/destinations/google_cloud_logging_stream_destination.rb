# frozen_string_literal: true

module AuditEvents
  module Streaming
    module Destinations
      class GoogleCloudLoggingStreamDestination < BaseStreamDestination
        def stream
          gcp_logger = AuditEvents::GoogleCloud::LoggingService::Logger.new
          response = gcp_logger.log(@destination.config["clientEmail"], @destination.secret_token, json_payload)

          ensure_success(response)
        end

        # Non-breaking: the Cloud Logging API accepts multiple `entries`, so a
        # batch maps to a multi-entry write.
        def stream_batch(event_bodies)
          gcp_logger = AuditEvents::GoogleCloud::LoggingService::Logger.new
          response = gcp_logger.log(
            destination.config["clientEmail"],
            destination.secret_token,
            batch_json_payload(event_bodies)
          )

          ensure_success(response)
        end

        private

        # Signet::AuthorizationError carries the response for a rejected token request,
        # and has none after googleauth's retries run out on a 5xx or network error.
        # make_creds raises RSAError for a malformed PEM.
        def classify_error(error)
          case error
          when Signet::AuthorizationError then error.response ? :auth : :connection
          when OpenSSL::PKey::RSAError then :invalid_config
          else super
          end
        end

        def json_payload
          { 'entries' => [log_entry] }.to_json
        end

        def batch_json_payload(event_bodies)
          { 'entries' => event_bodies.map { |body| log_entry_for(body) } }.to_json
        end

        def log_entry
          log_entry_for(parse_request_body)
        end

        def log_entry_for(json_payload)
          {
            'logName' => full_log_path,
            'resource' => {
              'type' => 'global'
            },
            'severity' => 'INFO',
            'jsonPayload' => json_payload
          }
        end

        def parse_request_body
          ::Gitlab::Json.safe_parse(request_body)
        rescue JSON::ParserError => e
          Gitlab::ErrorTracking.log_exception(e)
          # For audit events, we prefer to send the data even if it exceeds safe_parse limits
          # rather than lose critical compliance information
          ::Gitlab::Json.parse(request_body)
        end

        def full_log_path
          "projects/#{@destination.config['googleProjectIdName']}/logs/#{@destination.config['logIdName']}"
        end
      end
    end
  end
end
