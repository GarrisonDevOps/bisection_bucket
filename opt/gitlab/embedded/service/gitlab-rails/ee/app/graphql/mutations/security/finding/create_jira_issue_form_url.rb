# frozen_string_literal: true

module Mutations
  module Security
    module Finding
      class CreateJiraIssueFormUrl < BaseMutation
        graphql_name 'SecurityFindingJiraIssueFormUrlCreate'

        authorize :admin_vulnerability_external_issue_link

        authorize_granular_token permissions: :create_vulnerability_external_issue_link,
          boundary_argument: :project, boundary_type: :project

        field :jira_issue_form_url, GraphQL::Types::String,
          null: true,
          description: 'URL to Jira issue creation form with pre-filled vulnerability data.'

        argument :uuid,
          GraphQL::Types::String,
          required: true,
          description: 'UUID of the security finding to be used to create an issue.'

        argument :project, ::Types::GlobalIDType[::Project],
          required: true,
          description: 'ID of the project to attach the issue to.'

        def resolve(**params)
          project = authorized_find!(id: params[:project])
          params[:security_finding_uuid] = params.delete(:uuid)

          result = ::Security::Findings::CreateJiraIssueFormUrlService.new(project: project,
            current_user: current_user,
            params: params).execute

          {
            jira_issue_form_url: result.success? ? result.payload[:record] : nil,
            errors: result.errors
          }
        end
      end
    end
  end
end
