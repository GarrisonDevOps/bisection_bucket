# frozen_string_literal: true

module EE
  module Types
    module WorkItemType # rubocop:disable Gitlab/BoundedContexts -- Types::WorkItemType is CE class
      extend ActiveSupport::Concern

      prepended do
        field :promoted_to_epic_url, GraphQL::Types::String, null: true,
          description: 'URL of the epic that the work item has been promoted to.'

        field :duo_workflow_links,
          resolver: ::Resolvers::Ai::DuoWorkflows::WorkItemDuoWorkflowLinksResolver,
          description: 'GitLab Duo Agent Platform sessions linked to the work item.' do
            extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
          end

        field :agent_presence, ::Types::Ai::DuoWorkflows::AgentPresenceType,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Agent attribution for a work item created by a GitLab Duo Agent Platform session. ' \
            'Available to anyone who can read the work item; `userPermissions.readDuoWorkflow` tells whether ' \
            'the session itself can be opened. Returns null when no session created the work item or when the ' \
            '`agent_presence_consolidation` feature flag is disabled.'
      end

      def agent_presence
        return unless ::Feature.enabled?(:agent_presence_consolidation, object.resource_parent.root_ancestor)

        BatchLoader::GraphQL.for(object.id).batch do |work_item_ids, loader|
          workflows = agent_presence_workflows(work_item_ids)

          work_item_ids.each { |id| loader.call(id, workflows[id]) }
        end
      end

      private

      # The first `created` link wins; `source` links are the work item a session started from, not attribution.
      def agent_presence_workflows(work_item_ids)
        workflow_id_by_work_item = {}

        ::Ai::DuoWorkflows::WorkflowWorkItem.created_for_work_items_order_by_id_asc(work_item_ids).each do |link|
          workflow_id_by_work_item[link.work_item_id] ||= link.workflow_id
        end

        workflows = ::Ai::DuoWorkflows::Workflow.id_in(workflow_id_by_work_item.values.uniq)
          .with_preloaded_associations.to_a

        # `sourceLink` and `userPermissions.readDuoWorkflow` evaluate the session policy per session container.
        share_policy_subjects(workflows)
        ::Ai::DuoWorkflows::WorkflowPolicyPreloader.new(workflows, current_user).execute

        workflows = workflows.index_by(&:id)
        workflow_id_by_work_item.transform_values { |workflow_id| workflows[workflow_id] }
      end

      # DeclarativePolicy keeps one policy per container for the request, bound to the instance that first
      # reached it (here, the one that authorized the work item). The preload has to land on that instance.
      def share_policy_subjects(workflows)
        workflows.each do |workflow|
          workflow.project = ::Ability.policy_for(current_user, workflow.project).subject if workflow.project
          workflow.namespace = ::Ability.policy_for(current_user, workflow.namespace).subject if workflow.namespace
        end
      end
    end
  end
end
