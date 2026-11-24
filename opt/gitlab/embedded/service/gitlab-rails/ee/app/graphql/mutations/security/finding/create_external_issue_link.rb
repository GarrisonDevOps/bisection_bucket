# frozen_string_literal: true

module Mutations
  module Security
    module Finding
      class CreateExternalIssueLink < BaseMutation
        graphql_name 'SecurityFindingExternalIssueLinkCreate'

        authorize :admin_vulnerability_external_issue_link

        authorize_granular_token permissions: :create_vulnerability_external_issue_link,
          boundary_argument: :project, boundary_type: :project

        field :external_issue_link, Types::Vulnerability::ExternalIssueLinkType,
          null: true,
          description: 'Created external issue link.'

        argument :uuid,
          GraphQL::Types::String,
          required: true,
          description: 'UUID of the security finding to be used to create an issue.'

        argument :link_type,
          ::Types::Vulnerability::ExternalIssueLinkTypeEnum,
          required: true,
          description: 'Type of the external issue link.'

        argument :project, ::Types::GlobalIDType[::Project],
          required: true,
          description: 'ID of the project to attach the issue to.'

        argument :external_tracker,
          ::Types::Vulnerability::ExternalIssueLinkExternalTrackerEnum,
          required: true,
          description: 'External tracker type of the external issue link.'

        def resolve(**params)
          project = authorized_find!(id: params[:project])
          params[:security_finding_uuid] = params.delete(:uuid)

          result = ::Security::Findings::CreateExternalIssueLinkService.new(project: project,
            current_user: current_user,
            params: params).execute

          {
            external_issue_link: result.success? ? result.payload[:record] : nil,
            errors: result.errors
          }
        end
      end
    end
  end
end
