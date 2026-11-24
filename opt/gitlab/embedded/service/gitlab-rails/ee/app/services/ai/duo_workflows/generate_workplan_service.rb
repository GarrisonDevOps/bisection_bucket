# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Triggers the async, server-side "workplan" foundational flow for a
    # work item, so a plan is generated without opening Duo Chat. The Duo Workflow
    # Service runs the flow against ai-gateway and writes the plan into the work
    # item's Workplan widget.
    class GenerateWorkplanService
      include ::Gitlab::Utils::StrongMemoize

      # Mirrors Ai::DuoWorkflows::GenerateAgentConfigService's lease around
      # CreateAndStartWorkflowService - long enough to cover workflow creation
      # plus kicking off the start, short enough that a lease left
      # behind by a crashed request doesn't block a retry for long.
      LEASE_TTL = 2.minutes

      FEATURE_DISABLED_ERROR = 'Async workplan generation is not enabled for this project'
      PROJECT_REQUIRED_ERROR = 'Workplan generation is only available for project work items'
      WORKFLOW_ALREADY_RUNNING_ERROR = 'A workplan generation is already running for this work item'

      def initialize(work_item:, current_user:)
        @work_item = work_item
        @current_user = current_user
      end

      def execute
        return error(PROJECT_REQUIRED_ERROR, :project_required) unless project
        return error(FEATURE_DISABLED_ERROR, :feature_disabled) unless feature_enabled?

        start_workflow
      end

      private

      attr_reader :work_item, :current_user

      # workflow_already_running? is only a safe guard against two concurrent
      # calls landing here (e.g. a double-click, or a client retry racing the
      # original request) if the check and the create it guards happen inside
      # the same held lease - checking, then creating, then holding the lease
      # here would still let both callers pass the check before either
      # workflow row commits.
      def start_workflow
        lease_uuid = Gitlab::ExclusiveLease.new(lease_key, timeout: LEASE_TTL.to_i).try_obtain
        return error(WORKFLOW_ALREADY_RUNNING_ERROR, :workflow_already_running) unless lease_uuid

        begin
          return error(WORKFLOW_ALREADY_RUNNING_ERROR, :workflow_already_running) if workflow_already_running?

          ::Ai::DuoWorkflows::CreateAndStartWorkflowService.new(
            container: project,
            current_user: current_user,
            goal: goal,
            source_branch: project.default_branch,
            workflow_definition: workflow_definition,
            source_type: :work_item_workplan
          ).execute
        ensure
          Gitlab::ExclusiveLease.cancel(lease_key, lease_uuid)
        end
      end

      def lease_key
        "duo_workflows_generate_workplan:#{work_item.id}"
      end

      def project
        work_item.project
      end
      strong_memoize_attr :project

      # Actor must match CreateWorkflowService's own check against container.root_ancestor,
      # since Flipper actor gates don't cascade from a root group to its projects.
      def feature_enabled?
        ::Feature.enabled?(:workplan, project.root_ancestor)
      end

      def workflow_definition
        ::Ai::Catalog::FoundationalFlow.workplan_v1
      end
      strong_memoize_attr :workflow_definition

      def workflow_already_running?
        work_item.duo_workflows
          .with_workflow_definition(workflow_definition.reference)
          .with_non_terminal_status
          .exists?
      end

      def goal
        ::Ai::Catalog::GoalTemplates::Workplan.resolve(resource: work_item)
      end

      def error(message, reason)
        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
