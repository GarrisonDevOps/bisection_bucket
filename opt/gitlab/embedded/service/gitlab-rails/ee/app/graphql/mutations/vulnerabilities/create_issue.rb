# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class CreateIssue < BaseMutation
      graphql_name 'VulnerabilitiesCreateIssue'

      MAX_VULNERABILITIES = 100

      # This authorization is used for the **Issue only**.  The vulnerabilities
      # access is checked against :admin_vulnerability_issue_link
      authorize :create_issue

      authorize_granular_token permissions: :create_vulnerability_issue_link,
        boundary_argument: :project, boundary_type: :project

      field :issue,
        Types::IssueType,
        null: true,
        description: 'Issue created after mutation.'

      argument :project, ::Types::GlobalIDType[::Project],
        required: true,
        description: 'ID of the project to attach the issue to.'

      argument :vulnerability_ids,
        [::Types::GlobalIDType[::Vulnerability]],
        required: true,
        validates: { length: { minimum: 1, maximum: MAX_VULNERABILITIES } },
        description: "IDs of vulnerabilities to link to the given issue.  Up to #{MAX_VULNERABILITIES} can be provided."

      def resolve(vulnerability_ids:, project:)
        project = authorized_find!(id: project)

        issue_result = create_issue(project)

        return { errors: [issue_result[:message]] } if issue_result.error?

        result = create_issue_links(issue_result[:issue], vulnerabilities(vulnerability_ids))
        {
          issue: result.success? ? issue_result[:issue] : nil,
          errors: result.errors
        }
      end

      private

      def vulnerabilities(vulnerability_ids)
        vulnerabilities = Vulnerability.id_in(vulnerability_ids.map(&:model_id)).with_projects

        raise_resource_not_available_error! unless vulnerabilities.all? do |vulnerability|
          Ability.allowed?(current_user, :admin_vulnerability_issue_link, vulnerability)
        end

        vulnerabilities
      end

      def create_issue(project)
        ::Vulnerabilities::CreateIssueFromBulkActionService.new(
          project,
          current_user).execute
      end

      def create_issue_links(issue, vulnerabilities)
        ::VulnerabilityIssueLinks::BulkCreateService.new(current_user, issue, vulnerabilities).execute
      end
    end
  end
end
