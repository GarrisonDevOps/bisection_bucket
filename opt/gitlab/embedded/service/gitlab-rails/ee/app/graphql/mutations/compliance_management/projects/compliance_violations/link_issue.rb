# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module Projects
      module ComplianceViolations
        class LinkIssue < BaseMutation
          graphql_name 'LinkProjectComplianceViolationIssue'

          include Mutations::ResolvesIssuable

          authorize :update_compliance_violations_report
          authorize_granular_token permissions: :update_compliance_violations_report,
            boundary_argument: :violation_id, boundary: :project, boundary_type: :project

          field :violation,
            ::Types::ComplianceManagement::Projects::ComplianceViolationType,
            null: true,
            description: 'Updated project compliance violation.'

          argument :violation_id, ::Types::GlobalIDType[::ComplianceManagement::Projects::ComplianceViolation],
            required: true,
            description: 'Global ID of the project compliance violation.'

          argument :project_path, GraphQL::Types::ID,
            required: true,
            description: 'Full path of the project the issue belongs to.'

          argument :issue_iid, GraphQL::Types::String,
            required: true,
            description: 'IID of the issue to be linked.'

          def resolve(violation_id:, project_path:, issue_iid:)
            violation = authorized_find!(id: violation_id)
            issue = find_issue(project_path, issue_iid)

            service_response = execute_link_service(violation, issue)

            if service_response.success?
              success_response(violation)
            else
              error_response(violation, service_response.message)
            end
          end

          private

          def find_issue(project_path, issue_iid)
            issue = resolve_issuable(type: :issue, parent_path: project_path, iid: issue_iid)

            raise_resource_not_available_error! if issue.blank? || !Ability.allowed?(current_user, :read_issue, issue)

            issue
          end

          def execute_link_service(violation, issue)
            ::ComplianceManagement::Projects::ComplianceViolations::LinkIssueService.new(
              current_user: current_user,
              violation: violation,
              issue: issue
            ).execute
          end

          def success_response(violation)
            {
              violation: violation,
              errors: []
            }
          end

          def error_response(violation, message)
            {
              violation: violation,
              errors: [message]
            }
          end
        end
      end
    end
  end
end
