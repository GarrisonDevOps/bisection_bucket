# frozen_string_literal: true

module Mutations
  module Issues
    class SetEpic < Base
      graphql_name 'IssueSetEpic'

      authorize_granular_token permissions: :update_issue,
        boundary_argument: :project_path, boundary_type: :project

      argument :epic_id,
        ::Types::GlobalIDType[::Epic],
        required: false,
        description: 'Global ID of the epic to be assigned to the issue, ' \
          'epic will be removed if absent or set to null',
        deprecated: { reason: 'This will be replaced by WorkItem hierarchyWidget', milestone: '17.5' }

      def resolve(project_path:, iid:, epic_id: nil)
        issue = authorized_find!(project_path: project_path, iid: iid)
        project = issue.project

        epic = load_epic(epic_id)
        authorize_read_rights!(epic)

        begin
          ::Issues::UpdateService.new(container: project, current_user: current_user, params: { epic: epic })
            .execute(issue)
        rescue ::Gitlab::Access::AccessDeniedError
          raise_resource_not_available_error!
        rescue EE::Issues::BaseService::EpicAssignmentError => error
          issue.errors.add(:base, error.message)
        end

        {
          issue: issue,
          errors: issue.errors.full_messages
        }
      end

      private

      def load_epic(epic_id)
        return unless epic_id

        epic = Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(epic_id))
        # A missing record is a not-found error, so raise GraphQL::ExecutionError to match
        # the old `loads:` behaviour. Authorization failures use raise_resource_not_available_error!
        # (below) instead, so we don't leak that the record exists.
        raise GraphQL::ExecutionError, "No object found for `epicId: #{epic_id.to_s.inspect}`" unless epic

        epic
      end

      def authorize_read_rights!(epic)
        return unless epic.present?

        raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_epic, epic) &&
          Ability.allowed?(current_user, :read_epic, epic.group)
      end
    end
  end
end
