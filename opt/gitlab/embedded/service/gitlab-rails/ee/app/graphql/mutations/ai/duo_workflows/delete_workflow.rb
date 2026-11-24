# frozen_string_literal: true

module Mutations
  module Ai
    module DuoWorkflows
      class DeleteWorkflow < BaseMutation
        graphql_name 'DeleteDuoWorkflowsWorkflow'

        authorize :delete_duo_workflow
        authorize_granular_token permissions: :delete_duo_workflow,
          boundary: :user, boundary_type: :user

        argument :workflow_id, ::Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: true,
          description: 'Global ID of the workflow to delete.'

        field :success, GraphQL::Types::Boolean,
          null: false,
          description: 'Returns true if workflow was successfully deleted.'

        field :errors, [GraphQL::Types::String],
          null: false,
          description: 'List of errors that occurred whilst trying to delete the workflow.'

        def resolve(workflow_id:)
          workflow = authorized_find!(id: workflow_id)

          result = ::Ai::DuoWorkflows::DestroyWorkflowService.new(
            workflow: workflow, current_user: current_user
          ).execute

          {
            success: result.success?,
            errors: result.success? ? [] : Array(result.message)
          }
        end
      end
    end
  end
end
