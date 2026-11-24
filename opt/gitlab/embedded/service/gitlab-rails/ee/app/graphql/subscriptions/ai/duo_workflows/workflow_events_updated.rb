# frozen_string_literal: true

module Subscriptions
  module Ai
    module DuoWorkflows
      class WorkflowEventsUpdated < BaseSubscription
        include Gitlab::Graphql::Laziness

        payload_type ::Types::Ai::DuoWorkflows::WorkflowEventType

        argument :workflow_id, Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: true,
          description: 'Workflow ID to fetch duo workflow.'

        def authorized?(workflow_id:)
          unauthorized! unless current_user

          # Resolve the workflow once and pass it through to the ability
          # check so we don't issue a second find_by_gid lookup.
          #
          # The :read_duo_workflow ability is also granted to compliance
          # reviewers via WorkflowPolicy so they can read audit events
          # through the GraphQL field. Subscriptions stream live checkpoint
          # data (including chat messages and tool calls) which is broader
          # than audit-event scope, so restrict subscriptions to the actual
          # workflow owner. Pipeline-initiated workflows are excluded from
          # this subscription path; subscribers are always real users.
          workflow = published_workflow || force(GitlabSchema.find_by_gid(workflow_id))
          authorize_object_or_gid!(:read_duo_workflow, gid: workflow_id, object: workflow)

          unauthorized! unless workflow&.user_id == current_user.id

          true
        end

        # A workflow that changes status before writing its first checkpoint is published
        # on its own. Serve it as an empty event so status fields still resolve.
        def update(*)
          return ::Ai::DuoWorkflows::Checkpoint.new(workflow: object) if workflow_published?

          super
        end

        private

        def workflow_published?
          object.is_a?(::Ai::DuoWorkflows::Workflow)
        end

        def published_workflow
          workflow_published? ? object : object&.workflow
        end
      end
    end
  end
end
