# frozen_string_literal: true

module Mutations
  module WorkItems
    class GenerateReadinessScore < BaseMutation
      graphql_name 'WorkItemGenerateReadinessScore'
      description 'Scores the readiness of a work item asynchronously through a Duo Agent Platform flow, ' \
        'instead of Duo Chat. Available only when the `workplan` feature flag is enabled; ' \
        'returns an error otherwise.'

      authorize :update_work_item
      # Flow runs in a project, so only project work items are supported
      authorize_granular_token permissions: :update_work_item,
        boundary_argument: :id, boundary: :resource_parent, boundary_type: :project

      argument :id, ::Types::GlobalIDType[::WorkItem],
        required: true,
        description: 'Global ID of the work item to score readiness for.'

      field :workflow, ::Types::Ai::DuoWorkflows::WorkflowType,
        null: true,
        description: 'Duo Agent Platform workflow started to score the readiness.'

      def resolve(id:)
        work_item = authorized_find!(id: id)

        result = ::Ai::DuoWorkflows::GenerateReadinessScoreService.new(
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
