# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class SecretsCheck < ::Gitlab::Checks::BaseBulkChecker
        include ::Gitlab::InternalEventsTracking
        include ::Gitlab::Utils::StrongMemoize
        include ::Gitlab::Loggable

        ERROR_MESSAGES = {
          scan_initialization_error: 'Secret detection scan failed to initialize. %{error_msg}',
          sds_timeout: 'SDS returned a nil response or timed out. Falling back to SDS Gem'
        }.freeze

        LOG_MESSAGES = {
          secrets_check: 'Detecting secrets...'
        }.freeze

        def validate!
          return run_validation_dark_launch! if should_run_dark_launch?

          run_validation!
        end

        private

        def correlation_id
          @correlation_id ||= Labkit::Correlation::CorrelationId.current_id
        end

        def should_run_dark_launch?
          Feature.enabled?(:secret_detection_enable_spp_for_public_projects, project) &&
            public_project_without_spp?
        end

        # Returns true for public projects that don't have SPP enabled
        def public_project_without_spp?
          project.public? &&
            (!project.licensed_feature_available?(:secret_push_protection) ||
             !project.security_setting&.secret_push_protection_enabled?)
        end

        # Dark launch: Route SPP traffic through SDS for public projects to validate load handling.
        # This sends real production traffic to SDS without affecting the user experience or
        # blocking pushes. Used to test SDS capacity before full rollout.
        # Only runs for public projects that don't have SPP enabled or licensed.
        # See: https://gitlab.com/gitlab-org/gitlab/-/issues/551932
        def run_validation_dark_launch!
          start_time = Gitlab::Metrics::System.monotonic_time

          audit_logger.track_spp_scan_executed('dark-launch')

          logger.log_timed(LOG_MESSAGES[:secrets_check]) do
            payloads, _ = payload_processor.standardize_payloads
            break unless payloads

            extra_headers = {
              'x-correlation-id': correlation_id,
              'x-request-type': 'dark-launch'
            }
            sds_client.send_request_to_sds(payloads,
              exclusions: exclusions_manager.active_exclusions,
              extra_headers: extra_headers)
          end
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
          # Log the error but don't re-raise to prevent blocking pushes
          secret_detection_logger.error(
            build_structured_payload(
              message: "Secret push protection failed: #{e.message}",
              class: self.class.name,
              error_class: e.class.name
            )
          )
        ensure
          log_duration(start_time, 'run_validation_dark_launch!')
        end

        def run_validation!
          start_time = Gitlab::Metrics::System.monotonic_time

          return unless eligibility_checker.should_scan?

          audit_logger.track_spp_scan_executed('regular')

          lookup_map = {}

          logger.log_timed(LOG_MESSAGES[:secrets_check]) do
            payloads, lookup_map = payload_processor.standardize_payloads
            break unless payloads

            response = scan_for_secrets(payloads)

            # Log audit events for exlusions that were applied.
            audit_logger.log_applied_exclusions_audit_events(response.applied_exclusions)

            response_handler.format_response(response, lookup_map)
          rescue ::Gitlab::SecretDetection::Core::Ruleset::RulesetParseError,
            ::Gitlab::SecretDetection::Core::Ruleset::RulesetCompilationError => e
            handle_ruleset_error(e)
          rescue ::Gitlab::GitAccess::ForbiddenError => e
            raise e
          rescue TooManyChangedPathsError => e
            handle_too_many_changed_paths_error(e)
          rescue TooManyLinesError => e
            handle_too_many_lines_error(e)
          rescue StandardError => e
            handle_standard_error(e)
          end
        ensure
          log_duration(start_time, 'run_validation!')
        end

        ##############################
        # Exception Handlers

        def handle_ruleset_error(error)
          audit_logger.track_spp_ruleset_error
          audit_logger.log_spp_ruleset_error
          message = format(ERROR_MESSAGES[:scan_initialization_error], { error_msg: error.message })
          secret_detection_logger.error(build_structured_payload(message:))
        end

        def handle_too_many_changed_paths_error(error)
          audit_logger.track_spp_too_many_changed_paths_error(error.message, error.changed_paths_count)
          audit_logger.log_spp_too_many_changed_paths(error.changed_paths_count, error.changed_paths_threshold)
          Gitlab::Checks::SecretPushProtection::PostPushWarning
            .new(project.repository,
              changes_access.user_access.user,
              changes_access.protocol,
              error.changed_paths_count,
              error.changed_paths_threshold
            ).add_message
        end

        def handle_too_many_lines_error(error)
          audit_logger.track_spp_too_many_lines_error(error.message, error.lines_count)
          audit_logger.log_spp_too_many_lines(error.lines_count, error.lines_threshold)
          Gitlab::Checks::SecretPushProtection::PostPushWarning
            .new(project.repository,
              changes_access.user_access.user,
              changes_access.protocol,
              error.lines_count,
              error.lines_threshold
            ).add_message
        end

        def handle_standard_error(error)
          audit_logger.track_spp_standard_error_exception(error.class.name)
          audit_logger.log_spp_generic_scan_error
          Gitlab::Checks::SecretPushProtection::PostPushWarning
            .new(project.repository, changes_access.user_access.user, changes_access.protocol)
            .add_message
        end

        ##############################
        # Helpers

        # Performs secret detection scan using SDS client with fallback to gem scanner.
        def scan_for_secrets(payloads)
          extra_headers = {
            'x-correlation-id': correlation_id
          }

          response = sds_client.send_request_to_sds(payloads,
            exclusions: exclusions_manager.active_exclusions,
            extra_headers: extra_headers)

          if response.nil? || response_handler.timed_out?(response)
            secret_detection_logger.warn(
              build_structured_payload(
                message: ERROR_MESSAGES[:sds_timeout],
                class: self.class.name
              )
            )

            response = ::Gitlab::SecretDetection::Core::Scanner
              .new(rules: ruleset, logger: secret_detection_logger)
              .secrets_scan(
                payloads,
                timeout: logger.time_left,
                exclusions: exclusions_manager.active_exclusions
              )
          end

          response
        end

        def log_duration(start_time, method_name)
          duration = Gitlab::Metrics::System.monotonic_time - start_time
          secret_detection_logger.info(
            build_structured_payload(
              message: 'Secret push protection validation completed',
              method: method_name,
              duration_s: duration.round(1)
            )
          )
          audit_logger.track_spp_execution_time_in_seconds(duration.round(1))
        end

        def ruleset
          ::Gitlab::SecretDetection::Core::Ruleset.new(
            logger: secret_detection_logger
          ).rules
        end
        strong_memoize_attr :ruleset

        ############################
        # Audits and Event Logging
        # Creates audit events and tracks analytics for SPP activity

        def audit_logger
          @audit_logger ||= Gitlab::Checks::SecretPushProtection::AuditLogger.new(
            project: project,
            changes_access: changes_access
          )
        end

        def secret_detection_logger
          @secret_detection_logger ||= ::Gitlab::SecretDetectionLogger.build
        end

        ##############
        # Scan Checks
        # Determines whether SPP scanning should occur

        def eligibility_checker
          @eligibility_checker ||= Gitlab::Checks::SecretPushProtection::EligibilityChecker.new(
            project: project,
            changes_access: changes_access
          )
        end

        ##############
        # Payload Processor
        # Standardizes, parses, and processes diffs

        def payload_processor
          @payload_processor ||= Gitlab::Checks::SecretPushProtection::PayloadProcessor.new(
            project: project,
            changes_access: changes_access
          )
        end

        ##############
        # Response Handler
        # Handle the response depending on the status returned

        def response_handler
          @response_handler ||= Gitlab::Checks::SecretPushProtection::ResponseHandler.new(
            project: project,
            changes_access: changes_access
          )
        end

        ##############
        # Exclusions
        # Manages rule, path, and raw value exclusions

        def exclusions_manager
          @exclusions_manager ||= ::Gitlab::Checks::SecretPushProtection::ExclusionsManager.new(
            project: project,
            changes_access: changes_access
          )
        end

        ##############
        # Secret Detection Service Client
        # Manages communication with the external Secret Detection Service

        def sds_client
          @sds_client ||= Gitlab::Checks::SecretPushProtection::SecretDetectionServiceClient.new(
            project: project
          )
        end
      end
    end
  end
end
