# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class ResolveToolApprovalService
      LEASE_TTL = 2.minutes

      def initialize(workflow:, current_user:, approved:, fingerprint:, surface:)
        @workflow = workflow
        @current_user = current_user
        @approved = approved
        @fingerprint = fingerprint
        @surface = surface
      end

      def execute
        return error('Only the user who started the session can answer this request', :not_owner) unless owner?

        unless Ability.allowed?(current_user, :update_duo_workflow, workflow)
          return error('You are not allowed to update this session', :not_authorized)
        end

        with_lease do
          ::Gitlab::Database::LoadBalancing::SessionMap.current(workflow.load_balancer).use_primary do
            workflow.reload # rubocop:disable Cop/ActiveRecordAssociationReload -- the record, not an association
          end

          precondition_failure = check_preconditions
          next precondition_failure if precondition_failure

          continue
        end
      end

      private

      attr_reader :workflow, :current_user, :approved, :fingerprint, :surface

      def owner?
        workflow.invoked_by?(current_user)
      end

      def with_lease
        lease_uuid = Gitlab::ExclusiveLease.new(lease_key, timeout: LEASE_TTL.to_i).try_obtain
        return error('This request is already being processed', :decision_in_progress) unless lease_uuid

        begin
          yield
        ensure
          Gitlab::ExclusiveLease.cancel(lease_key, lease_uuid)
        end
      end

      def check_preconditions
        unless workflow.tool_call_approval_required?
          return error('The session is not waiting for a tool approval', :not_approvable)
        end

        pending = PendingToolApproval.for(workflow)
        return stale_request unless pending && pending.fingerprint == fingerprint

        # The status and checkpoint only change once the runtime picks the run
        # up, so an applied decision is remembered in the callback context;
        # a second decision must see it.
        return stale_request if messaging_answered?

        nil
      end

      def messaging_answered?
        workflow.messaging_callback_context&.dig('answered_approval') == fingerprint
      end

      def stale_request
        error('This approval request has already been answered', :stale_request)
      end

      def continue
        tool_names = PendingToolApproval.for(workflow).tool_names

        result = ExecuteRunService.new(
          workflow,
          event: { type: :approval, approved: approved },
          provision_membership: true
        ).execute

        return error(result.message, :continue_failed) if result.error?

        # Its own key, so a request the resumed run raises next can never be overwritten here.
        if workflow.messaging_callback_context.present?
          workflow.merge_messaging_callback_context!(
            'answered_approval' => fingerprint,
            'answered_decision' => approved ? 'approved' : 'denied'
          )
        end

        audit_decision(tool_names)

        result
      end

      # approval_scope tells compliance consumers this decision applied to one
      # call only, unlike the session allow-list UpdateToolCallApprovalsService audits.
      def audit_decision(tool_names)
        verb = approved ? 'Approved' : 'Denied'

        ::Gitlab::Audit::Auditor.audit(
          name: approved ? 'duo_tool_call_approved' : 'duo_tool_call_denied',
          author: current_user,
          scope: workflow.resource_parent,
          target: workflow,
          target_details: "#{workflow.workflow_definition} session #{workflow.id}",
          message: "#{verb} tool call: #{tool_names.join(', ')}",
          additional_details: { approval_source: 'user_explicit', approval_scope: 'once', approval_surface: surface }
        )
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
      end

      def lease_key
        "duo_workflows_resolve_tool_approval:#{workflow.id}"
      end

      def error(message, reason)
        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
