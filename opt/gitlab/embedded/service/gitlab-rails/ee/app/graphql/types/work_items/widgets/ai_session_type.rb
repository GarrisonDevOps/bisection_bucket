# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- Disabling widget level authorization
      class AiSessionType < BaseObject
        graphql_name 'WorkItemWidgetAiSession'
        description 'Represents an AI session widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        field :duo_workflows,
          ::Types::Ai::DuoWorkflows::WorkflowType.connection_type,
          null: true,
          description: 'GitLab Duo Agent Platform flow sessions associated with the work item. ' \
            'Chat sessions are excluded.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :can_read_duo_workflows,
          GraphQL::Types::Boolean,
          null: true,
          complexity: 0,
          experiment: { milestone: '19.6' },
          description: 'Indicates whether the current user has the access needed to read GitLab Duo Agent ' \
            'Platform flow sessions of the work item. Each session is still authorized individually.'

        field :agent_presence,
          ::Types::Ai::DuoWorkflows::AgentPresenceType,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Presence of the newest GitLab Duo Agent Platform session of the work item that has ' \
            'not finished. Available to anyone who can read the work item; ' \
            '`userPermissions.readDuoWorkflow` tells whether the session itself can be opened. ' \
            'Batch-loaded, so it can be requested for many work items in one request.'

        # rubocop:disable GraphQL/ExtractType -- flat, so one card needs no nested selection
        field :agent_presence_status,
          ::Types::Ai::DuoWorkflows::WorkflowStatusEnum,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Status of the session in `agentPresence`.'

        field :agent_presence_human_status,
          GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Human-readable status of the session in `agentPresence`.'
        # rubocop:enable GraphQL/ExtractType

        def agent_presence
          latest_active_workflow
        end

        def agent_presence_status
          ::Gitlab::Graphql::Lazy.with_value(latest_active_workflow) { |workflow| workflow&.status }
        end

        def agent_presence_human_status
          ::Gitlab::Graphql::Lazy.with_value(latest_active_workflow) { |workflow| workflow&.human_status_name }
        end

        # Display hint only: every read_duo_workflow rule in Ai::DuoWorkflows::WorkflowPolicy needs one of
        # these on the parent, and each session is still authorized on its own. Guarded by ai_session_type_spec.rb.
        def can_read_duo_workflows
          return false unless current_user

          parent = object.work_item.resource_parent

          %i[duo_workflow access_duo_agentic_chat read_agent_artifacts].any? do |ability|
            Ability.allowed?(current_user, ability, parent)
          end
        end

        private

        def latest_active_workflow
          BatchLoader::GraphQL.for(object.work_item.id).batch(key: :latest_active_workflow) do |work_item_ids, loader|
            workflows = ::WorkItems::Widgets::AiSession.latest_active_workflows_for(work_item_ids)

            work_item_ids.each { |id| loader.call(id, workflows[id]) }
          end
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
