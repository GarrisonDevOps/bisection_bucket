# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowEventsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        authorizes_object!

        # Default page size of 1 retains the tail-only behaviour that protects
        # against unbounded checkpoint serialisation on every poll. Callers that
        # need to page through history can pass `first: N, after: <cursor>`.
        DEFAULT_EVENTS_PAGE_SIZE = 1

        # Every row is a full checkpoint rebuilt from its blob chain, so cost and
        # response size grow with rows times session length. Larger `first` values
        # are clamped, not rejected, so cursor paging still reaches all history.
        MAX_EVENTS_PAGE_SIZE = 5

        type Types::Ai::DuoWorkflows::WorkflowEventType, null: false

        argument :workflow_id, Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: true,
          description: 'Array of request IDs to fetch.'

        def resolve(**args)
          return ::Ai::DuoWorkflows::Checkpoint.none unless current_user

          if object.is_a?(::Project)
            project = object
            return ::Ai::DuoWorkflows::Checkpoint.none unless Ability.allowed?(current_user, :duo_workflow, project)
          end

          Gitlab::Graphql::Lazy.with_value(find_object(id: args[:workflow_id])) do |workflow|
            if can_get_workflow_checkpoints?(workflow, project)
              # Both checkpoint tables have a composite primary key due to daily
              # partitioning, which breaks keyset cursor pagination (the
              # SimpleOrderBuilder loses the workflow_id scope when rebuilding
              # WHERE conditions from the cursor). Offset pagination is correct
              # here: the result set is bounded by the 30-day retention window
              # and stable cursors are not required.
              # When no pagination arguments are supplied the connection layer
              # applies the field's default_page_size: DEFAULT_EVENTS_PAGE_SIZE,
              # returning only the latest checkpoint and keeping per-poll cost O(1).
              offset_pagination(workflow.present.checkpoint_events)
            else
              ::Ai::DuoWorkflows::Checkpoint.none
            end
          end
        end

        private

        def find_object(id:)
          GitlabSchema.find_by_gid(id)
        end

        def can_get_workflow_checkpoints?(workflow, project)
          return false unless workflow

          return false unless Ability.allowed?(current_user, :read_duo_workflow, workflow)

          return false if project && workflow.project != project

          true
        end
      end
    end
  end
end
