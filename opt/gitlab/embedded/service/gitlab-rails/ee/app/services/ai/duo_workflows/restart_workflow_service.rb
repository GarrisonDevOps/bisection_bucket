# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Runs a failed or stopped workflow again as a new session with the same flow,
    # goal, noteable, source, privileges and trigger. The original record is left as
    # it is: reusing its id would let a workload from the old run that is still alive
    # write into the new one.
    class RestartWorkflowService
      include ::Ai::DuoWorkflows::Concerns::LinkArtifact

      LEASE_TTL = 15.seconds

      # Everything the flow execution path would otherwise default or leave unset.
      # `execution_mode` is deliberately absent: CreateWorkflowService only accepts it
      # from a sealed classification, and the new session runs in the background anyway.
      COPIED_ATTRIBUTES = %i[
        agent_privileges pre_approved_agent_privileges image web_search_enabled
        trigger_source trigger_flow_trigger_id trigger_flow_schedule_id trigger_event_type
        source_type source_link source_client_name source_client_version
      ].freeze

      def initialize(workflow:, current_user:, item_consumer:, service_account:)
        @workflow = workflow
        @current_user = current_user
        @item_consumer = item_consumer
        @service_account = service_account
      end

      def execute
        unless Ability.allowed?(@current_user, :restart_duo_workflow, @workflow)
          return ServiceResponse.error(message: 'Can not restart workflow', reason: :forbidden)
        end

        goal_result = validate_goal
        # Every goal check failure describes the merge request, so return them under one
        # reason and let the caller mask them alike.
        return ServiceResponse.error(message: goal_result.message, reason: :invalid_goal) if goal_result&.error?

        # Overlapping requests (a double click, a client retry) would each start a
        # session. The lease is kept on success so a repeat within the TTL is rejected too.
        lease_uuid = Gitlab::ExclusiveLease.new(lease_key, timeout: LEASE_TTL.to_i).try_obtain
        unless lease_uuid
          return ServiceResponse.error(message: 'Workflow is already being restarted', reason: :conflict)
        end

        result = ::Ai::Catalog::Flows::ExecuteService.new(
          project: @workflow.project,
          current_user: @current_user,
          params: flow_params
        ).execute

        if result.error?
          Gitlab::ExclusiveLease.cancel(lease_key, lease_uuid)
          return result
        end

        new_workflow = result.payload[:workflow]
        link_artifact(new_workflow, @workflow, link_type: :source)
        notify_messaging_adapter(new_workflow)
        audit_event(new_workflow)

        ServiceResponse.success(payload: { workflow: new_workflow, workload_id: result.payload[:workload_id] })
      end

      private

      # A flow with a source branch resolver checks out the branch its resolver finds for
      # the goal, and falls back to the default branch when it finds none (for example, the
      # Business Logic flow once the merge request is closed or merged). Run the flow's goal
      # check first, as a new start does. Flows without a resolver restart as before.
      def validate_goal
        foundational_flow = @item_consumer.item.foundational_flow
        return unless foundational_flow&.source_branch_resolver

        foundational_flow.validate_start_request(
          container: @workflow.project, goal: @workflow.goal, client_executed: false
        )
      end

      def lease_key
        "duo_workflows_restart:#{@workflow.id}"
      end

      def flow_params
        {
          item_consumer: @item_consumer,
          service_account: @service_account,
          execute_workflow: true,
          event_type: @workflow.trigger_event_type || 'api_execution',
          user_prompt: @workflow.goal,
          issue_id: @workflow.issue&.iid,
          merge_request_id: @workflow.merge_request&.iid,
          messaging_callback_context: messaging_callback_context,
          parent_workflow: @workflow.parent_workflow,
          workflow_attributes: workflow_attributes
        }
      end

      # CreateWorkflowService sets flow itself, and only when it attaches the parent.
      def workflow_attributes
        attributes = @workflow.slice(*COPIED_ATTRIBUTES).symbolize_keys
        attributes.delete(:trigger_source) if @workflow.triggered_by_flow?
        foundational_flow = @item_consumer.item.foundational_flow
        ::Ai::DuoWorkflows::DeclaredPrivileges.apply!(attributes, foundational_flow) if foundational_flow
        attributes
      end

      def messaging_callback_context
        context = @workflow.messaging_callback_context
        return if context.blank?

        context.except(*::Ai::Messaging::Adapters::Base::SESSION_STATE_KEYS)
      end

      # The mention and Slack pipelines fire this hook once the flow is enqueued so
      # the adapter can link the triggering note and post its progress marker.
      # Restart enqueues through ExecuteService directly, so fire it here.
      def notify_messaging_adapter(new_workflow)
        context = new_workflow.messaging_callback_context
        return if context.blank?

        adapter_class = ::Ai::Messaging::AdapterRegistry[context['adapter']]
        return unless adapter_class

        adapter_class.from_callback_context(context).on_flow_enqueued(callback_context: context, workflow: new_workflow)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: new_workflow.id)
      end

      def audit_event(new_workflow)
        ::Gitlab::Audit::Auditor.audit(
          name: 'duo_session_restarted',
          author: @current_user,
          scope: @workflow.project,
          target: @workflow,
          target_details: "#{@workflow.workflow_definition} session #{@workflow.id} restarted as #{new_workflow.id}",
          message: 'Restarted Duo session'
        )
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: @workflow.id)
      end
    end
  end
end
