# frozen_string_literal: true

module Gitlab
  module Checks
    module PushRules
      class JiraVerificationCheck < ::Gitlab::Checks::BaseBulkChecker
        include Gitlab::Utils::StrongMemoize

        def validate!
          return unless jira_enabled?
          return if skip_for_empty_project?

          changes_access.single_change_accesses.each do |single_change_access|
            validate_single_change_access(single_change_access)
          end

        rescue StandardError => e
          raise ::Gitlab::GitAccess::ForbiddenError, e.message
        end

        private

        def validate_single_change_access(single_change_access)
          commits = single_change_access.commits

          commits.each_with_index do |commit, _index|
            # Check timeout (timeout mechanism may need to be reimplemented)
            jira_verification_check(commit)
          end
        end

        def jira_enabled?
          return false unless jira_integration

          jira_integration.activated? && jira_check_enabled?
        end

        # Skip Jira verification for the initial commit to an empty project
        # created via the web interface (e.g., "Initialize with README" during
        # project creation, or SAST/Secret Detection initialization).
        # This avoids blocking system-generated commits that cannot carry
        # Jira issue references.
        def skip_for_empty_project?
          project.empty_repo? && updated_from_web?
        end

        def jira_verification_check(commit)
          # Only proceed if at least one check is enabled
          return unless any_jira_check_enabled?

          # Extract Jira issues from commit message - do this only once
          jira_issue_keys = extract_jira_issue_keys(commit.safe_message)

          raise ::Gitlab::GitAccess::ForbiddenError, "No Jira issue found in commit message" if jira_issue_keys.empty?

          issue_key = jira_issue_keys.first

          # Find the Jira issue - do this only once
          issue = find_jira_issue(issue_key)

          # Check 1: Jira exists (if enabled)
          if jira_exists_check_enabled?
            verify_issue_exists(issue_key, issue)
          else
            # If issue doesn't exist and we need it for other checks, return early
            return unless issue.present?
          end

          # Check 2: Verify assignee (if enabled)
          verify_assignee(issue, commit) if jira_assignee_check_enabled?

          # Check 3: Verify status (if enabled)
          verify_status(issue) if jira_status_check_enabled?
        end

        def verify_issue_exists(issue_key, issue)
          return if issue.present?

          raise ::Gitlab::GitAccess::ForbiddenError, "Jira issue #{issue_key} does not exist"
        end

        def verify_assignee(issue, commit)
          assignee = issue.assignee
          return if assignee.blank?

          # Match by email or name
          committer_email = commit.author_email
          committer_name = commit.author_name

          # In Jira Server, assignee is a hash with displayName and emailAddress
          # In Jira Cloud, assignee is a hash with displayName and sometimes emailAddress
          assignee_email = assignee.respond_to?(:emailAddress) ? assignee.emailAddress : nil
          assignee_name = assignee.respond_to?(:displayName) ? assignee.displayName : nil

          return if assignee_email == committer_email || assignee_name == committer_name

          raise ::Gitlab::GitAccess::ForbiddenError,
            "Jira issue #{issue.key} is not assigned to you. " \
              "It is assigned to #{assignee_name || 'someone else'}"
        end

        def verify_status(issue)
          current_status = issue.status.name
          allowed_statuses = jira_allowed_statuses

          return unless allowed_statuses.present? && allowed_statuses.exclude?(current_status)

          raise ::Gitlab::GitAccess::ForbiddenError,
            "Jira issue #{issue.key} has status '#{current_status}', " \
              "which is not in the list of allowed statuses: #{allowed_statuses.join(', ')}"
        end

        def extract_jira_issue_keys(message)
          pattern = jira_integration.reference_pattern
          return [] unless pattern

          if pattern.respond_to?(:scan)
            # UntrustedRegexp has its own scan method
            pattern.scan(message).flatten.uniq
          else
            # Regular Regexp - use String#scan
            message.scan(pattern).flatten.uniq
          end
        end

        def find_jira_issue(issue_key)
          jira_integration.find_issue(issue_key)
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, issue_key: issue_key)
          raise ::Gitlab::GitAccess::ForbiddenError,
            "Failed to connect to Jira to verify issue #{issue_key}. Error: #{e.message}"
        end

        def jira_integration
          @jira_integration ||= find_jira_integration
        end

        def find_jira_integration
          # Try project-level integration first
          integration = project.jira_integration
          return integration if integration&.activated?

          # Try group-level integration (including ancestors)
          if project.group
            project.group.self_and_ancestors.each do |group|
              integration = group.jira_integration
              return integration if integration&.activated?
            end
          end

          # Try instance-level integration
          ::Integrations::Jira.instance_level(project.organization)
        end

        def jira_check_enabled?
          jira_integration&.data_fields&.jira_check_enabled
        end

        def jira_exists_check_enabled?
          jira_integration&.data_fields&.jira_exists_check_enabled
        end

        def jira_assignee_check_enabled?
          jira_integration&.data_fields&.jira_assignee_check_enabled
        end

        def jira_status_check_enabled?
          jira_integration&.data_fields&.jira_status_check_enabled
        end

        def jira_allowed_statuses
          jira_integration&.data_fields&.jira_allowed_statuses || []
        end

        def any_jira_check_enabled?
          jira_exists_check_enabled? || jira_assignee_check_enabled? || jira_status_check_enabled?
        end
      end
    end
  end
end
