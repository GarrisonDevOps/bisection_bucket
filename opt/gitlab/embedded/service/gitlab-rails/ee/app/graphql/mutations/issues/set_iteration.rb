# frozen_string_literal: true

module Mutations
  module Issues
    class SetIteration < Base
      graphql_name 'IssueSetIteration'

      authorize_granular_token permissions: :update_issue,
        boundary_argument: :project_path, boundary_type: :project

      argument :iteration_id,
        ::Types::GlobalIDType[::Iteration],
        required: false,
        description: <<~DESC
                 Iteration to assign to the issue.
        DESC

      def resolve(project_path:, iid:, iteration_id: nil)
        issue = authorized_find!(project_path: project_path, iid: iid)
        project = issue.project

        iteration = load_iteration(iteration_id)
        authorize_read_iteration!(iteration)

        ::Issues::UpdateService.new(container: project, current_user: current_user, params: { iteration: iteration })
          .execute(issue)

        {
          issue: issue,
          errors: issue.errors.full_messages
        }
      end

      private

      def authorize_read_iteration!(iteration)
        return unless iteration.present?

        raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_iteration, iteration)
      end

      def load_iteration(iteration_id)
        return unless iteration_id

        iteration = Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(iteration_id))

        unless iteration
          raise GraphQL::ExecutionError,
            "No object found for `iterationId: #{iteration_id.to_s.inspect}`"
        end

        iteration
      end
    end
  end
end
