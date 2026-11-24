# frozen_string_literal: true

module Ai
  module FlowTriggers
    # Where a new workflow would sit in a chain of workflows started by other workflows.
    class CallerContext
      include ::Gitlab::Utils::StrongMemoize

      MAX_TRIGGER_DEPTH = 10
      MAX_CHILD_WORKFLOWS_PER_PARENT = 5
      # Caps the whole tree under one root. Depth and breadth alone would allow about 5^10 workflows.
      MAX_DESCENDANT_WORKFLOWS_PER_ROOT = 30

      attr_reader :parent_workflow

      # `workflow_id` comes from the client-supplied `X-Gitlab-Duo-Workflow-Id` header, so it is only
      # trusted when `user` may update that workflow.
      def self.authorized_parent_workflow(workflow_id, user)
        return unless workflow_id.present? && user

        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        workflow if workflow && Ability.allowed?(user, :update_duo_workflow, workflow)
      end

      def self.authorized_parent_workflow_for_request(user)
        authorized_parent_workflow(::Gitlab::ApplicationContext.current_context_attribute(:duo_workflow_id), user)
      end

      def initialize(parent_workflow:)
        @parent_workflow = parent_workflow
      end

      # Depth of the new child: a workflow without a parent has depth 0.
      def depth
        return ancestors.size if truncated?

        ancestors.count { |workflow| !workflow.triggered_by_verification? }
      end

      def depth_exceeded?
        depth >= MAX_TRIGGER_DEPTH
      end

      def breadth_exceeded?
        parent_workflow.child_workflows.count >= MAX_CHILD_WORKFLOWS_PER_PARENT
      end

      # Counts workflows in any status, so restarted and failed runs use up the budget too.
      def chain_size_exceeded?
        root_workflow.descendant_workflows.limit(MAX_DESCENDANT_WORKFLOWS_PER_ROOT).count >=
          MAX_DESCENDANT_WORKFLOWS_PER_ROOT
      end

      # Nil when the chain is longer than the walk, which is rejected as too deep.
      def root_workflow
        ancestors.last unless truncated?
      end

      # A flow-triggered root means its parent was deleted, which must not reset the chain.
      def root_human
        root = root_workflow
        return unless root
        return if root.triggered_by_flow?
        return if ::Ai::DuoWorkflows::Workflow::AUTONOMOUS_TRIGGER_SOURCES.include?(root.trigger_source)

        root.user if root.user.human?
      end

      def same_root_namespace?(container)
        parent_container = parent_workflow.project || parent_workflow.namespace
        return false unless parent_container && container

        parent_container.root_ancestor == container.root_ancestor
      end

      private

      # Parent first, root last.
      def ancestors
        workflows = []
        workflow = parent_workflow

        while workflow && workflows.size <= MAX_TRIGGER_DEPTH
          workflows << workflow
          workflow = workflow.parent_workflow
        end

        workflows
      end
      strong_memoize_attr :ancestors

      def truncated?
        ancestors.last.parent_workflow_id.present?
      end
    end
  end
end
