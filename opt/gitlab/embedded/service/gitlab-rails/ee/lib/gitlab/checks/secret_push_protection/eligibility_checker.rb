# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class EligibilityChecker < ::Gitlab::Checks::SecretPushProtection::Base
        SPECIAL_COMMIT_FLAG = /\[skip secret push protection\]/i

        def should_scan?
          # Return early and do not perform the check:
          #   1. unless license is ultimate
          #   2. unless application setting is enabled
          #   3. unless project setting is enabled
          #   4. if it is a delete branch/tag operation, as it would require scanning the entire revision history
          #   5. if protocol is not http/ssh,
          #      or with web protocol, if gitaly_context['enable_secrets_check'] is not passed
          #   6. if options are passed for us to skip the check
          return false unless license_available?
          return false unless secret_push_protection_available?
          return false if includes_full_revision_history?
          return false unless use_diff_scan?

          if skip_secret_detection_commit_message?
            audit_logger.log_skip_secret_push_protection(_("commit message"))
            audit_logger.track_spp_skipped("commit message")
            return false
          end

          if skip_secret_detection_push_option?
            audit_logger.log_skip_secret_push_protection(_("push option"))
            audit_logger.track_spp_skipped("push option")
            return false
          end

          true
        end

        private

        def license_available?
          project.licensed_feature_available?(:secret_push_protection)
        end

        def secret_push_protection_available?
          Gitlab::CurrentSettings.current_application_settings.secret_push_protection_available &&
            secret_push_protection_enabled?
        end

        def secret_push_protection_enabled?
          return true if Gitlab::CurrentSettings.current_application_settings.secret_push_protection_enforced

          project.security_setting&.secret_push_protection_enabled ||
            project.security_scan_profile_for(:secret_detection, :git_push_event).present?
        end

        def includes_full_revision_history?
          Gitlab::Git.blank_ref?(changes_access.changes.first[:newrev])
        end

        def http_or_ssh_protocol?
          %w[http ssh].include?(changes_access.protocol)
        end

        def use_diff_scan?
          http_or_ssh_protocol? || secrets_check_enabled_for_web_requests?
        end

        def secrets_check_enabled_for_web_requests?
          return false if changes_access.gitaly_context.nil?

          changes_access.gitaly_context['enable_secrets_check'] == true
        end

        def skip_secret_detection_commit_message?
          changes_access.commits.any? { |commit| commit.safe_message =~ SPECIAL_COMMIT_FLAG }
        end

        def skip_secret_detection_push_option?
          changes_access.push_options&.get(:secret_push_protection, :skip_all)
        end
      end
    end
  end
end
