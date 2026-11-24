# frozen_string_literal: true

module Mutations
  module WorkItems
    class ResolveWorkplanQuestions < BaseMutation
      graphql_name 'WorkItemResolveWorkplanQuestions'
      description 'Resolves every open question the workplan generation flow asked on a work item, ' \
        'without resuming the flow. Plain flow comments are converted to resolvable threads first. ' \
        'Available only when the `workplan` feature flag is enabled; returns an error otherwise.'

      authorize :update_work_item
      authorize_granular_token permissions: :update_work_item,
        boundary_argument: :id, boundary: :resource_parent, boundary_type: :project

      argument :id, ::Types::GlobalIDType[::WorkItem],
        required: true,
        description: 'Global ID of the work item whose workplan questions to resolve.'

      field :work_item, ::Types::WorkItemType,
        null: true,
        description: 'Work item after the questions were resolved.'

      def resolve(id:)
        work_item = authorized_find!(id: id)

        result = ::Ai::DuoWorkflows::ResolveWorkplanQuestionsService.new(
          work_item: work_item,
          current_user: current_user
        ).execute

        {
          work_item: result.success? ? work_item : nil,
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
