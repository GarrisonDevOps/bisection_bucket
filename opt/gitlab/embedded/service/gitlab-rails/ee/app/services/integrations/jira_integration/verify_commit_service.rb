# frozen_string_literal: true

module Integrations
  module JiraIntegration
    class VerifyCommitService
      attr_reader :project, :current_user, :params

      def initialize(project, current_user = nil, params = {})
        @project = project
        @current_user = current_user
        @params = params
      end

      # Extract Jira issue keys from a commit message
      def extract_issue_keys(message)
        return [] unless message.present? && jira_integration&.activated?

        pattern = jira_integration.reference_pattern
        return [] unless pattern

        message.scan(pattern).flatten.uniq
      end

      # Verify if an issue exists in Jira
      def verify_issue_exists(issue_key)
        return false unless jira_integration&.activated?

        issue = jira_integration.find_issue(issue_key)
        issue.present?
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, issue_key: issue_key)
        false
      end

      # Check if the user is assignee of the issue
      def verify_user_is_assignee(issue_key, user_email, user_name)
        return false unless jira_integration&.activated?

        issue = jira_integration.find_issue(issue_key)
        return false unless issue.present?

        assignee = issue.assignee
        return false unless assignee.present?

        # In Jira Server, assignee is a hash with displayName and emailAddress
        # In Jira Cloud, assignee is a hash with displayName and sometimes emailAddress
        assignee_email = assignee.respond_to?(:emailAddress) ? assignee.emailAddress : nil
        assignee_name = assignee.respond_to?(:displayName) ? assignee.displayName : nil

        assignee_email == user_email || assignee_name == user_name
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, issue_key: issue_key)
        false
      end

      # Check if the issue has an allowed status
      def verify_issue_status(issue_key, allowed_statuses)
        return false if allowed_statuses.blank?
        return false unless jira_integration&.activated?

        issue = jira_integration.find_issue(issue_key)
        return false unless issue.present? && issue.status.present?

        current_status = issue.status.name
        allowed_statuses.include?(current_status)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, issue_key: issue_key)
        false
      end

      # Get the current status of an issue
      def issue_status(issue_key)
        return unless jira_integration&.activated?

        issue = jira_integration.find_issue(issue_key)
        return unless issue.present? && issue.status.present?

        issue.status.name
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, issue_key: issue_key)
        nil
      end

      private

      def jira_integration
        @jira_integration ||= find_jira_integration
      end

      def active_integration(integration)
        return unless integration&.activated?

        integration
      end

      def find_jira_integration
        # Try project-level integration first
        integration = project.jira_integration
        result = active_integration(integration)
        return result if result

        # Try group-level integration
        if project.group
          integration = project.group.jira_integration
          result = active_integration(integration)
          return result if result
        end

        # Try instance-level integration
        integration = ::Integrations::Jira.instance_level(project.organization)
        active_integration(integration)
      end
    end
  end
end
