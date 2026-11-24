# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Remediation merge requests a maintainer closed without merging. The bot's own
    # no-maintainer auto-close (closed by the service account) is excluded, so those are
    # still retried.
    class UserClosedRemediationsFinder
      include Gitlab::Utils::StrongMemoize

      # @param project [Project] The project to search within
      def initialize(project:)
        @project = project
      end

      # @param source_branch [String]
      # @return [Boolean]
      def dismissed_branch?(source_branch)
        return false unless service_account

        project.merge_requests
          .closed
          .authored(service_account)
          .not_closed_by(service_account)
          .by_source_branch(source_branch)
          .exists?
      end

      # @param vulnerability [Vulnerability]
      # @return [ActiveRecord::Relation]
      def for_vulnerability(vulnerability)
        return MergeRequest.none unless service_account

        vulnerability.merge_requests
          .closed
          .authored(service_account)
          .not_closed_by(service_account)
      end

      private

      attr_reader :project

      def service_account
        project.dependency_management_service_account
      end
      strong_memoize_attr :service_account
    end
  end
end
