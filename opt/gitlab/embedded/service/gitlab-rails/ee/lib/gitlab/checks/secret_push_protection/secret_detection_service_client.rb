# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class SecretDetectionServiceClient < ::Gitlab::Checks::SecretPushProtection::Base
        include ::Gitlab::Loggable

        LOG_MESSAGES = {
          sds_disabled: "SDS is disabled: FF: %{sds_ff_enabled}, SaaS: %{saas_feature_enabled}, " \
            "Non-Dedicated: %{is_not_dedicated}"
        }.freeze

        attr_accessor :should_use_sds, :sds_client, :settings, :sds_host, :sds_auth_token

        def initialize(project:)
          super(project: project, changes_access: nil)
          @should_use_sds = nil
          @sds_client = nil
          @settings = ::Gitlab::CurrentSettings.current_application_settings
          @sds_host = settings.secret_detection_service_url
          @sds_auth_token = settings.secret_detection_service_auth_token
        end

        # Determines if SDS should be used (feature flags + instance checks).
        def use_secret_detection_service?
          return should_use_sds unless should_use_sds.nil?

          sds_ff_enabled = Feature.enabled?(:use_secret_detection_service, project)
          saas_feature_enabled = ::Gitlab::Saas.feature_available?(:secret_detection_service)
          is_not_dedicated = !settings.gitlab_dedicated_instance

          should_use_sds = sds_ff_enabled && saas_feature_enabled && is_not_dedicated && sds_host.present?

          unless should_use_sds
            msg = format(LOG_MESSAGES[:sds_disabled], { sds_ff_enabled:, saas_feature_enabled:, is_not_dedicated: })
            secret_detection_logger.info(build_structured_payload(message: msg))
          end

          should_use_sds
        end

        def setup_sds_client
          return unless use_secret_detection_service?
          return if sds_client.present?

          begin
            @sds_client = ::Gitlab::SecretDetection::GRPC::Client.new(
              sds_host,
              secure: sds_auth_token.present?,
              logger: secret_detection_logger
            )
          rescue StandardError => e
            ::Gitlab::ErrorTracking.track_exception(e)
            @sds_client = nil
          end
        end

        # Send payloads to SDS asynchronously or directly (ignores response).
        def send_request_to_sds(payloads, exclusions: {}, extra_headers: {})
          setup_sds_client
          return if sds_client.nil?

          request = build_sds_request(payloads, exclusions: exclusions)

          request_type = extra_headers[:'x-request-type'] || 'standard'
          secret_detection_logger.info("Sending request to SDS with type: #{request_type}")

          sds_client.run_scan(request: request, auth_token: sds_auth_token, extra_headers: extra_headers)
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
          # Return an empty response on error
          nil
        end

        private

        # Build an array of gRPC Exclusion messages from our exclusion hashes.
        def build_exclusions(exclusions: {})
          exclusions.flat_map do |_type_key, exclusion_list|
            exclusion_list.map do |exclusion|
              ::Gitlab::SecretDetection::GRPC::Exclusion.new(
                exclusion_type: exclusion.exclusion_type,
                value: exclusion.value
              )
            end
          end
        end

        # Puts the entire gRPC request object together
        def build_sds_request(payloads, exclusions: {}, tags: [])
          ::Gitlab::SecretDetection::GRPC::ScanRequest.new(
            payloads: payloads,
            timeout_secs: ::Gitlab::SecretDetection::GRPC::Client::REQUEST_TIMEOUT_SECONDS,
            exclusions: build_exclusions(exclusions: exclusions),
            tags: tags
          )
        end
      end
    end
  end
end
