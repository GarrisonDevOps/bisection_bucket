# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class OpenRemediationsFinder
      # Initializes the finder for finding open remediation merge requests
      #
      # @param project [Project] The project to search within
      def initialize(project:)
        @project = project
      end

      # Executes the finder and returns open merge requests
      # created by the dependency management service account
      #
      # @return [ActiveRecord::Relation] Relation of open merge requests
      def execute
        scope
      end

      private

      attr_reader :project

      def scope
        service_account = project.dependency_management_service_account
        return MergeRequest.none unless service_account

        # rubocop: disable CodeReuse/ActiveRecord -- eager loading is the finder's concern
        MergeRequest
          .of_projects(project)
          .authored(service_account)
          .opened
          .preload_project_and_latest_diff
          .preload(vulnerability_merge_request_links: { vulnerability: [:findings, :sbom_occurrences] })
        # rubocop: enable CodeReuse/ActiveRecord
      end
    end
  end
end
