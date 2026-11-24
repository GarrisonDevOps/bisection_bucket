# frozen_string_literal: true

module EE
  module Integrations
    module JiraTrackerData
      extend ActiveSupport::Concern

      # These boolean fields exist as direct columns in the database
      # See migration db/migrate/20250716063945_add_jira_verification_fields_to_jira_tracker_data.rb

      # Ensure nil is converted to false for consistent boolean behavior
      def jira_check_enabled
        !!read_attribute(:jira_check_enabled)
      end

      def jira_exists_check_enabled
        !!read_attribute(:jira_exists_check_enabled)
      end

      def jira_assignee_check_enabled
        !!read_attribute(:jira_assignee_check_enabled)
      end

      def jira_status_check_enabled
        !!read_attribute(:jira_status_check_enabled)
      end

      # Handle jira_allowed_statuses_string as a comma-separated string in the database
      # but expose it as an array in the application
      def jira_allowed_statuses
        return [] if read_attribute(:jira_allowed_statuses_string).blank?

        read_attribute(:jira_allowed_statuses_string).split(',').map(&:strip)
      end

      def jira_allowed_statuses=(value)
        statuses_array = Array(value).map(&:strip).reject(&:blank?).uniq
        write_attribute(:jira_allowed_statuses_string, statuses_array.join(','))
      end

      def jira_allowed_statuses_as_string
        return '' if jira_allowed_statuses.blank?

        jira_allowed_statuses.join(',')
      end

      def jira_allowed_statuses_as_string=(value)
        self.jira_allowed_statuses = value.to_s.split(',').map(&:strip).reject(&:blank?).uniq
      end
    end
  end
end
