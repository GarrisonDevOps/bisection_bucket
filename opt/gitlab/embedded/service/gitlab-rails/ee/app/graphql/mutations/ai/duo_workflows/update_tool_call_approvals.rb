# frozen_string_literal: true

module Mutations
  module Ai
    module DuoWorkflows
      class UpdateToolCallApprovals < BaseMutation
        graphql_name 'UpdateDuoWorkflowToolCallApprovals'

        include ::Mutations::Ai::DuoWorkflows::RequiresIdentityVerification

        authorize :update_duo_workflow
        authorize_granular_token permissions: :update_duo_workflow,
          boundary: :user, boundary_type: :user

        argument :workflow_id,
          ::Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: true,
          description: 'Global ID of the workflow to update.'

        argument :tool_name,
          GraphQL::Types::String,
          required: true,
          description: 'Name of the tool to approve.'

        argument :tool_call_args, # rubocop:disable Graphql/JSONType -- Different tools will have different call args
          GraphQL::Types::JSON,
          required: false,
          description: 'Arguments for the tool call.'

        argument :pattern,
          GraphQL::Types::String,
          required: false,
          description: 'Glob pattern to approve for matching tool call arguments.'

        argument :approval_source,
          Types::Ai::DuoWorkflows::ToolCallApprovalSourceEnum,
          required: false,
          description: 'Source of the approval decision, for audit purposes.',
          experiment: { milestone: '19.3' }

        field :workflow,
          Types::Ai::DuoWorkflows::WorkflowType,
          null: true,
          description: 'Updated workflow with new tool approvals.'

        field :errors,
          [GraphQL::Types::String],
          null: false,
          description: 'Errors encountered during update.'

        def resolve(workflow_id:, tool_name:, tool_call_args: nil, pattern: nil, approval_source: nil)
          unless tool_call_args.nil? ^ pattern.nil?
            return { workflow: nil, errors: ['Exactly one of toolCallArgs or pattern must be provided'] }
          end

          workflow = ::Gitlab::Graphql::Lazy.force(find_object(id: workflow_id))

          raise_if_identity_verification_required!(workflow&.resource_parent)
          authorize!(workflow)

          result = ::Ai::DuoWorkflows::UpdateToolCallApprovalsService.new(
            workflow: workflow,
            tool_name: tool_name,
            tool_call_args: tool_call_args,
            pattern: pattern,
            approval_source: approval_source,
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
