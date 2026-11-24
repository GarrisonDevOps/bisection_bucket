# frozen_string_literal: true

module Mutations
  module Epics
    class AddIssue < Base
      graphql_name 'EpicAddIssue'

      include Mutations::ResolvesIssuable

      authorize :admin_epic_relation
      authorize_granular_token permissions: :create_epic_issue, boundary_argument: :group_path,
        boundary_type: :group

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: 'Full path of the project the issue belongs to.'

      argument :issue_iid, GraphQL::Types::String,
        required: true,
        description: 'IID of the issue to be added.'

      field :epic_issue,
        Types::EpicIssueType,
        null: true,
        description: 'Epic-issue relationship.'

      def resolve(group_path:, iid:, project_path:, issue_iid:)
        epic = authorized_find!(group_path: group_path, iid: iid)
        issue = resolve_issuable(type: :issue, parent_path: project_path, iid: issue_iid)
        service = create_epic_issue(epic, issue)
        epic_issue = service[:status] == :success ? find_epic_issue(epic, issue) : nil
        error_message = service[:message]

        {
          epic_issue: epic_issue,
          errors: error_message.present? ? [error_message] : []
        }
      end

      private

      def create_epic_issue(epic, issue)
        ::WorkItems::LegacyEpics::EpicIssues::CreateService.new(epic, current_user, { target_issuable: issue }).execute
      end

      def find_epic_issue(epic, issue)
        ::WorkItems::LegacyEpics::WorkItemAsEpic.new(epic.work_item)
          .find_child_issue(issue.id)
      end
    end
  end
end
