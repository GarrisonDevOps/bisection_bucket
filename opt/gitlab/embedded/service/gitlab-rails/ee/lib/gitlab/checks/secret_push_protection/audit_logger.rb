# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class AuditLogger < ::Gitlab::Checks::SecretPushProtection::Base
        include ::Gitlab::InternalEventsTracking

        # Audit event names
        AUDIT_EVENT_SKIP_SECRET_PUSH_PROTECTION = 'skip_secret_push_protection'
        AUDIT_EVENT_SPP_TOO_MANY_CHANGED_PATHS = 'spp_too_many_changed_paths'
        AUDIT_EVENT_SPP_TOO_MANY_LINES = 'spp_too_many_lines'
        AUDIT_EVENT_SPP_SCAN_TIMEOUT = 'spp_scan_timeout'
        AUDIT_EVENT_SPP_RULESET_ERROR = 'spp_ruleset_error'
        AUDIT_EVENT_SPP_INVALID_INPUT = 'spp_invalid_input'
        AUDIT_EVENT_SPP_GENERIC_SCAN_ERROR = 'spp_generic_scan_error'
        AUDIT_EVENT_SPP_PUSH_BLOCKED = 'spp_push_blocked'
        AUDIT_EVENT_PROJECT_SECURITY_EXCLUSION_APPLIED = 'project_security_exclusion_applied'

        # Restricts the audit event payload when a push leaks a large number of secrets
        MAX_AUDITED_BLOCKED_PUSH_FINDINGS = 100

        # Internal event names
        INTERNAL_EVENT_SKIP_SECRET_PUSH_PROTECTION = 'skip_secret_push_protection'
        INTERNAL_EVENT_DETECT_SECRET_TYPE_ON_PUSH = 'detect_secret_type_on_push'
        INTERNAL_EVENT_SPP_SCAN_EXECUTED = 'spp_scan_executed'
        INTERNAL_EVENT_SPP_SCAN_PASSED = 'spp_scan_passed'
        INTERNAL_EVENT_SPP_PUSH_BLOCKED_SECRETS_FOUND = 'spp_push_blocked_secrets_found'
        INTERNAL_EVENT_SPP_PUSH_BLOCKED_SECRETS_FOUND_WITH_ERRORS = 'spp_push_blocked_secrets_found_with_errors'
        INTERNAL_EVENT_CALCULATE_CHANGED_PATHS = 'calculate_changed_paths_in_secret_push_protection'
        INTERNAL_EVENT_SPP_TOTAL_EXECUTION_TIME = 'spp_total_execution_time'
        INTERNAL_EVENT_SPP_STANDARD_ERROR_EXCEPTION = 'spp_standard_error_exception_encountered'
        INTERNAL_EVENT_SPP_TOO_MANY_CHANGED_PATHS_ERROR = 'spp_too_many_changed_paths_error_encountered'
        INTERNAL_EVENT_SPP_TOO_MANY_LINES_ERROR = 'spp_too_many_lines_error_encountered'
        INTERNAL_EVENT_SPP_RULESET_ERROR = 'spp_ruleset_error_encountered'

        def initialize(project:, changes_access:)
          super
          @user = changes_access.user_access.user
        end

        def log_skip_secret_push_protection(skip_method)
          branch_name = changes_access.single_change_accesses.first.branch_name
          message = "#{_('Secret push protection skipped via')} #{skip_method} on branch #{branch_name}"

          log_audit_event(name: AUDIT_EVENT_SKIP_SECRET_PUSH_PROTECTION, message: message)
        end

        def log_spp_push_blocked(findings)
          log_audit_event(
            name: AUDIT_EVENT_SPP_PUSH_BLOCKED,
            message: _('Secret push protection blocked the push.'),
            target_details: nil, # Push is rejected, so the ref never moves and a comparison URL would not resolve
            additional_details: {
              refs: changes_access.changes.pluck(:ref).uniq, # rubocop:disable CodeReuse/ActiveRecord -- it's an array, not AR model
              findings: findings.first(MAX_AUDITED_BLOCKED_PUSH_FINDINGS),
              findings_truncated: findings.size > MAX_AUDITED_BLOCKED_PUSH_FINDINGS
            }
          )
        end

        def log_spp_too_many_changed_paths(changed_paths_count, changed_paths_threshold)
          message = format(
            _("Secret push protection was skipped: %{changed_paths_count} changed paths exceeds " \
              "the threshold of %{changed_paths_threshold}."),
            changed_paths_count: changed_paths_count,
            changed_paths_threshold: changed_paths_threshold
          )

          log_audit_event(name: AUDIT_EVENT_SPP_TOO_MANY_CHANGED_PATHS, message: message)
        end

        def log_spp_too_many_lines(lines_count, lines_threshold)
          message = format(
            _("Secret push protection was skipped: %{lines_count} lines count exceeds " \
              "the threshold of %{lines_threshold}."),
            lines_count: lines_count,
            lines_threshold: lines_threshold
          )

          log_audit_event(name: AUDIT_EVENT_SPP_TOO_MANY_LINES, message: message)
        end

        def log_spp_scan_timeout
          log_audit_event(
            name: AUDIT_EVENT_SPP_SCAN_TIMEOUT,
            message: _('Secret push protection scan timed out. The push was accepted.')
          )
        end

        def log_spp_ruleset_error
          log_audit_event(
            name: AUDIT_EVENT_SPP_RULESET_ERROR,
            message: _('Secret push protection encountered a ruleset parse or compile error.')
          )
        end

        def log_spp_invalid_input
          log_audit_event(
            name: AUDIT_EVENT_SPP_INVALID_INPUT,
            message: _('Secret push protection skipped due to invalid input.')
          )
        end

        def log_spp_generic_scan_error
          log_audit_event(
            name: AUDIT_EVENT_SPP_GENERIC_SCAN_ERROR,
            message: _('Secret push protection encountered an unexpected scan error.')
          )
        end

        def log_exclusion_audit_event(exclusion)
          log_audit_event(
            name: AUDIT_EVENT_PROJECT_SECURITY_EXCLUSION_APPLIED,
            message: "An exclusion of type (#{exclusion.type}) with value (#{exclusion.value}) was " \
              "applied in Secret push protection",
            target: exclusion,
            # The exclusion is the target, so the push comparison URL does not describe it.
            target_details: nil
          )
        end

        def log_applied_exclusions_audit_events(applied_exclusions)
          return unless should_log_audit_events?

          # `applied_exclusions` can contain only a single kind of objects
          if applied_exclusions.any?(::Security::ProjectSecurityExclusion)
            log_exclusions(applied_exclusions)
          else
            log_sds_exclusions(applied_exclusions)
          end
        end

        def track_spp_skipped(skip_method)
          track_internal_event(
            INTERNAL_EVENT_SKIP_SECRET_PUSH_PROTECTION,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              label: skip_method
            }
          )
        end

        def track_secret_found(secret_type)
          track_internal_event(
            INTERNAL_EVENT_DETECT_SECRET_TYPE_ON_PUSH,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              label: secret_type
            }
          )
        end

        def track_spp_scan_executed(scan_type)
          track_internal_event(
            INTERNAL_EVENT_SPP_SCAN_EXECUTED,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              label: scan_type
            }
          )
        end

        def track_spp_scan_passed
          track_internal_event(
            INTERNAL_EVENT_SPP_SCAN_PASSED,
            user: @user,
            project: project,
            namespace: project.namespace
          )
        end

        def track_spp_push_blocked_secrets_found(number)
          track_internal_event(
            INTERNAL_EVENT_SPP_PUSH_BLOCKED_SECRETS_FOUND,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              value: number
            }
          )
        end

        def track_spp_push_blocked_secrets_found_with_errors(number)
          track_internal_event(
            INTERNAL_EVENT_SPP_PUSH_BLOCKED_SECRETS_FOUND_WITH_ERRORS,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              value: number
            }
          )
        end

        def track_changed_paths_calculated(changed_paths_count)
          track_internal_event(
            INTERNAL_EVENT_CALCULATE_CHANGED_PATHS,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              value: changed_paths_count
            }
          )
        end

        def track_spp_execution_time_in_seconds(number)
          track_internal_event(
            INTERNAL_EVENT_SPP_TOTAL_EXECUTION_TIME,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              value: number
            }
          )
        end

        def track_spp_standard_error_exception(exception_class)
          track_internal_event(
            INTERNAL_EVENT_SPP_STANDARD_ERROR_EXCEPTION,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              label: exception_class
            }
          )
        end

        def track_spp_too_many_changed_paths_error(message, changed_paths_count)
          track_internal_event(
            INTERNAL_EVENT_SPP_TOO_MANY_CHANGED_PATHS_ERROR,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              label: message,
              value: changed_paths_count
            }
          )
        end

        def track_spp_too_many_lines_error(message, lines_count)
          track_internal_event(
            INTERNAL_EVENT_SPP_TOO_MANY_LINES_ERROR,
            user: @user,
            project: project,
            namespace: project.namespace,
            additional_properties: {
              label: message,
              value: lines_count
            }
          )
        end

        def track_spp_ruleset_error
          track_internal_event(
            INTERNAL_EVENT_SPP_RULESET_ERROR,
            user: @user,
            project: project,
            namespace: project.namespace
          )
        end

        private

        def should_log_audit_events?
          project.licensed_feature_available?(:audit_events)
        end

        def log_exclusions(exclusions)
          exclusions.each { |exclusion| log_exclusion_audit_event(exclusion) }
        end

        def log_sds_exclusions(exclusions)
          exclusions_by_value = sds_exclusions_by_value(exclusions)

          exclusions.each do |exclusion|
            project_security_exclusion = exclusions_by_value[exclusion.value]

            log_exclusion_audit_event(project_security_exclusion) unless project_security_exclusion.nil?
          end
        end

        def log_audit_event(
          name:,
          message:,
          target: project,
          target_details: generate_target_details,
          additional_details: {}
        )
          return unless should_log_audit_events?

          ::Gitlab::Audit::Auditor.audit(
            name: name,
            author: @user,
            target: target,
            scope: project,
            message: message,
            target_details: target_details,
            additional_details: additional_details
          )
        end

        def generate_target_details
          changes = changes_access.changes
          old_rev = changes.first&.dig(:oldrev)
          new_rev = changes.last&.dig(:newrev)

          return project.name if old_rev.nil? || new_rev.nil?

          ::Gitlab::Utils.append_path(
            ::Gitlab::Routing.url_helpers.root_url,
            ::Gitlab::Routing.url_helpers.project_compare_path(project, from: old_rev, to: new_rev)
          )
        end

        # One query for the whole batch, instead of one per applied exclusion.
        def sds_exclusions_by_value(applied_exclusions)
          values = applied_exclusions.map(&:value)

          return {} if values.empty?

          project.security_exclusions.where(value: values).group_by(&:value).transform_values(&:first) # rubocop:disable CodeReuse/ActiveRecord -- Need to be able to link GRPC::Exclusion to ProjectSecurityExclusion
        end
      end
    end
  end
end
