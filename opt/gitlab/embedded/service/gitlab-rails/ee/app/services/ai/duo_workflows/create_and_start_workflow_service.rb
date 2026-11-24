# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CreateAndStartWorkflowService
      include ::Gitlab::Utils::StrongMemoize
      include Concerns::AuditedDrop

      MISSING_WORKFLOW_DEFINITION_ERROR = 'Workflow definition cannot be blank'
      MISSING_SOURCE_BRANCH_ERROR = 'Source branch cannot be blank'
      MISSING_SERVICE_ACCOUNT_ERROR = 'Could not resolve the service account for this flow'
      FLOW_NOT_ENABLED_ERROR = 'Workflow not enabled for this project/namespace'
      EXECUTION_DENIED_ERROR = 'Can not execute workflow'
      DROP_AUDIT_EVENT_MESSAGE = 'Duo session failed: session start did not succeed'

      def initialize(
        container:, current_user:, goal:, source_branch:, workflow_definition:, parent_workflow: nil,
        additional_context: nil, source_type: :flow_trigger)
        @container = container
        @current_user = current_user
        @goal = goal
        @source_branch = source_branch
        @workflow_definition = workflow_definition
        @parent_workflow = parent_workflow
        @additional_context = additional_context
        @source_type = source_type
      end

      def execute
        return validation if validation.error?

        create_result = ::Ai::DuoWorkflows::CreateWorkflowService.new(
          container: container,
          current_user: current_user,
          params: create_workflow_params,
          started_flow: started_flow
        ).execute

        if create_result.error?
          return error(
            create_result.message,
            create_result.payload[:reason] || create_result.reason || :create_workflow
          )
        end

        workflow = create_result[:workflow]

        start_result = start_workflow(workflow)

        if start_result.error?
          return error(
            start_result.message,
            start_result.payload[:reason] || start_result.reason || :start_workflow
          )
        end

        workload_id = start_result.payload[:workload_id]
        message = start_result.message

        ServiceResponse.success(message: message, payload: { workflow: workflow, workload_id: workload_id })
      end

      private

      attr_reader :container, :current_user, :workflow_definition, :goal, :source_branch, :parent_workflow,
        :additional_context, :source_type

      # A workflow whose start failed is not running, so leaving it at `created` makes status
      # a lie until CleanStuckWorkflowsService reaps it half an hour later. Both failure modes
      # drop it: most return an error response, but a composite identity conflict raises.
      def start_workflow(workflow)
        result = if execution_allowed?(workflow)
                   ::Ai::DuoWorkflows::ExecuteRunService.new(
                     workflow,
                     event: { type: :input, text: workflow.goal },
                     provision_membership: true,
                     source_branch: source_branch,
                     context: { additional_context: additional_context }
                   ).execute
                 else
                   error(EXECUTION_DENIED_ERROR, :feature_unavailable)
                 end

        drop_workflow(workflow) if result.error?

        result
      rescue StandardError
        drop_workflow(workflow)
        raise
      end

      def execution_allowed?(workflow)
        runtime = ::Ai::DuoWorkflows::ExecuteRunService.runtime_for(workflow.workflow_definition, user: workflow.user)

        runtime != :workhorse || Ability.allowed?(current_user, :execute_duo_workflow_in_ci, workflow)
      end

      def drop_workflow(workflow)
        drop_and_audit(workflow, drop_reason: 'start_failed', author: current_user, message: DROP_AUDIT_EVENT_MESSAGE)
      end

      def validation
        return error(MISSING_WORKFLOW_DEFINITION_ERROR, :invalid_workflow_definition) if workflow_definition.blank?
        return error(MISSING_SOURCE_BRANCH_ERROR, :invalid_source_branch) if source_branch.blank?
        return error(FLOW_NOT_ENABLED_ERROR, :flow_not_enabled) unless flow_configured_for_container?
        return error(MISSING_SERVICE_ACCOUNT_ERROR, :invalid_service_account) if service_account.nil?

        ServiceResponse.success
      end
      strong_memoize_attr :validation

      def flow_configured_for_container?
        catalog_item_id = workflow_definition.catalog_item&.id

        return false if catalog_item_id.blank?

        container.duo_foundational_flows_enabled &&
          container.enabled_flow_catalog_item_ids.include?(catalog_item_id)
      end

      def error(message, reason, payload = {})
        ServiceResponse.error(message: message, reason: reason, payload: payload)
      end

      def create_workflow_params
        params = {
          goal: goal,
          workflow_definition: workflow_definition_reference,
          agent_privileges: workflow_definition.agent_privileges,
          pre_approved_agent_privileges: workflow_definition.pre_approved_agent_privileges,
          allow_agent_to_request_user: workflow_definition.allow_agent_to_request_user,
          environment: workflow_definition.environment,
          service_account: service_account,
          source_type: source_type
        }
        params[:parent_workflow] = parent_workflow if parent_workflow
        params
      end

      def workflow_definition_reference
        workflow_definition.foundational_flow_reference
      end

      # The additional context can pick the flow (e.g. a code review's depth), so the session records that flow.
      def started_flow
        ::Ai::DuoWorkflows::FoundationalFlowStartParamsResolver.call(
          workflow_definition_reference, container, user: current_user, additional_context: additional_context
        )
      end

      def service_account
        return unless workflow_definition.catalog_item

        result = ::Ai::Catalog::ItemConsumers::ResolveServiceAccountService.new(
          container: container,
          item: workflow_definition.catalog_item
        ).execute

        return if result.error?

        result.payload.fetch(:service_account)
      end
      strong_memoize_attr :service_account
    end
  end
end
