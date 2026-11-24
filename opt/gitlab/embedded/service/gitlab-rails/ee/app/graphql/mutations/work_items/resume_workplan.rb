# frozen_string_literal: true

module Mutations
  module WorkItems
    class ResumeWorkplan < BaseMutation
      graphql_name 'WorkItemResumeWorkplan'
      description 'Resumes a paused workplan generation flow that is awaiting input, sending the replies left ' \
        'on the questions the flow asked. Available only when the `workplan` feature flag is ' \
        'enabled; returns an error otherwise.'

      authorize :update_work_item
      # Async workplan generation only supports project work items (the flow
      # runs in a project), so only a project boundary is declared.
      authorize_granular_token permissions: :update_work_item,
        boundary_argument: :id, boundary: :resource_parent, boundary_type: :project

      argument :id, ::Types::GlobalIDType[::WorkItem],
        required: true,
        description: 'Global ID of the work item whose workplan generation to resume.'

      field :workflow, ::Types::Ai::DuoWorkflows::WorkflowType,
        null: true,
        description: 'Duo Agent Platform workflow that was resumed.'

      def resolve(id:)
        work_item = authorized_find!(id: id)

        result = ::Ai::DuoWorkflows::ResumeWorkplanService.new(
          work_item: work_item,
          current_user: current_user
        ).execute

        {
          workflow: result.success? ? result.payload[:workflow] : nil,
          errors: result.error? ? Array(result.message) : []
        }
      end

      private

      def find_object(id:)
        GitlabSchema.object_from_id(id, expected_type: ::WorkItem).sync
      end
    end
  end
end
