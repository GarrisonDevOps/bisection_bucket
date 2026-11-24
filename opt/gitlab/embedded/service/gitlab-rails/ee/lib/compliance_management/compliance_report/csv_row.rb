# frozen_string_literal: true

module ComplianceManagement
  module ComplianceReport
    class CsvRow
      def initialize(commit, user, from, to, options = {})
        @user = user
        @commit = commit
        @from = from
        @to = to
        @merge_request = options[:merge_request]
        @committer_users = {}
      end

      attr_reader :from, :to, :commit, :user, :merge_request
      attr_writer :committer_users

      def sha
        commit&.sha
      end

      def author
        commit&.author&.name || merge_request&.author&.name
      end

      def committer
        raw_committer_name = commit&.committer_name
        return raw_committer_name unless raw_committer_name

        # Try to find GitLab user by email for consistent name
        if commit&.committer_email.present?
          user = @committer_users[commit.committer_email]
          return user.name if user
        end

        raw_committer_name
      end

      def committed_at
        return unless commit&.committed_date

        # Ensure consistent UTC formatting with millisecond precision
        commit.committed_date.utc.xmlschema(3)
      end

      def group
        commit&.project&.namespace&.name || merge_request&.project&.group&.name
      end

      def project
        commit&.project&.name || merge_request&.project&.name
      end

      def merge_commit
        merge_request&.merge_commit_sha
      end

      def merge_request_id
        merge_request&.id
      end

      def merged_by
        merge_request&.metrics&.merged_by&.name
      end

      def merged_at
        merge_request&.merged_at&.xmlschema if merge_request&.merged_at
      end

      def pipeline
        merge_request&.metrics&.pipeline_id
      end

      def approvers
        merge_request&.approved_by_users&.map(&:name)&.sort&.join(" | ")
      end
    end
  end
end
