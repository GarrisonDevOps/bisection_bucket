# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowBranchesResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        authorize :read_duo_workflow

        authorize_granular_token permissions: :read_duo_workflow, boundary: :user, boundary_type: :user

        # Nullable: a granular token without the permission nulls the branches rather
        # than failing the query on a non-nullable list.
        type [Types::Ai::DuoWorkflows::BranchType], null: true

        argument :workflow_id, Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: true,
          description: 'Global ID of the session.'

        argument :thread_ts, GraphQL::Types::String,
          required: true,
          description: 'Identifier of the checkpoint that introduced a user message, from ' \
            '`DuoMessage.threadTs`. Must be a message on the current branch of the session. ' \
            'Returns the other attempts at the same turn, so the branch that message belongs ' \
            'to is excluded.'

        def resolve(workflow_id:, thread_ts:)
          workflow = authorized_find!(id: workflow_id)

          return [] unless workflow.incremental_blob_gate.read?
          # Branches carry the retried turns' messages; a metadata-retention session serves none.
          return [] if workflow.metadata_content_retention?

          workflow.workflow_branches(thread_ts)
        rescue ::Ai::DuoWorkflows::Workflow::OffCurrentBranchError => error
          raise ::Gitlab::Graphql::Errors::ArgumentError, error.message
        end
      end
    end
  end
end
