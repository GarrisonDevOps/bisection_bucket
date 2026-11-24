# frozen_string_literal: true

module Mutations
  module Ai
    module DuoWorkflows
      class UpdateAgentPrivileges < BaseMutation
        graphql_name 'UpdateDuoWorkflowAgentPrivileges'

        include ::Mutations::Ai::DuoWorkflows::RequiresIdentityVerification

        authorize :update_duo_workflow
        authorize_granular_token permissions: :update_duo_workflow, boundary: :user, boundary_type: :user

        argument :workflow_id,
          ::Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: true,
          description: 'Global ID of the workflow to update.'

        argument :agent_privileges,
          [GraphQL::Types::Int],
          required: false,
          description: 'Replaces the set of actions the agent is allowed to perform.',
          validates: { length: { maximum: Types::BaseArgument::MAX_ARRAY_SIZE } }

        argument :pre_approved_agent_privileges,
          [GraphQL::Types::Int],
          required: false,
          description: 'Replaces the set of actions the agent can perform without asking for approval.',
          validates: { length: { maximum: Types::BaseArgument::MAX_ARRAY_SIZE } }

        field :workflow,
          Types::Ai::DuoWorkflows::WorkflowType,
          null: true,
          description: 'Updated workflow.'

        field :errors,
          [GraphQL::Types::String],
          null: false,
          description: 'Errors encountered during update.'

        def resolve(workflow_id:, agent_privileges: nil, pre_approved_agent_privileges: nil)
          workflow = ::Gitlab::Graphql::Lazy.force(find_object(id: workflow_id))

          raise_if_identity_verification_required!(workflow&.resource_parent)
          authorize!(workflow)

          result = ::Ai::DuoWorkflows::UpdateAgentPrivilegesService.new(
            workflow: workflow,
            agent_privileges: agent_privileges,
            pre_approved_agent_privileges: pre_approved_agent_privileges,
            current_user: current_user
          ).execute

          if result.success?
            { workflow: result.payload[:workflow], errors: [] }
          else
            { workflow: nil, errors: [result.message] }
          end
        end
      end
    end
  end
end
