# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class UpdateAgentPrivilegesService
      include Concerns::GovernanceResolution

      def initialize(workflow:, current_user:, agent_privileges: nil, pre_approved_agent_privileges: nil)
        @workflow = workflow
        @agent_privileges = agent_privileges
        @pre_approved_agent_privileges = pre_approved_agent_privileges
        @current_user = current_user
      end

      def execute
        unless Ability.allowed?(@current_user, :update_duo_workflow, @workflow)
          return error_response("Can not update workflow", :unauthorized)
        end

        limit_to_declared_privileges
        clamp_error = clamp_privileges_to_governance
        return clamp_error if clamp_error

        update_agent_privileges
      end

      private

      def limit_to_declared_privileges
        flow = DeclaredPrivileges.foundational_flow(@workflow.workflow_definition)
        return unless flow
        return unless @agent_privileges || @pre_approved_agent_privileges

        @agent_privileges &&= DeclaredPrivileges.limit(@agent_privileges, flow)
        granted = @agent_privileges || @workflow.agent_privileges
        @pre_approved_agent_privileges =
          DeclaredPrivileges.limit(@pre_approved_agent_privileges || @workflow.pre_approved_agent_privileges, flow) &
          granted
      end

      # Callers cannot be trusted to self-report privileges, so intersect them with the
      # governance resolution. The surface only selects which rule column is read.
      #
      # Returns an error ServiceResponse when governance cannot be resolved
      # (nothing is persisted), or nil when the update may proceed.
      def clamp_privileges_to_governance
        return unless @agent_privileges || @pre_approved_agent_privileges
        return unless governance_container
        return unless known_privileges?(@agent_privileges, @pre_approved_agent_privileges)
        # Load-bearing now the flag check is gone: an ungoverned session must not clamp to web rules.
        return if ::Ai::ToolRules::GovernanceSurface.ungoverned?(governance_surface)

        result = resolve_governance_with_retry(resolution_service, workflow_id: @workflow.id)

        unless result&.success?
          Gitlab::AppLogger.error(
            message: governance_failure_message('rejecting agent privileges update', result),
            workflow_id: @workflow.id
          )

          # Retrying cannot change a surface, so do not tell the caller to.
          if result&.reason == :ungoverned_surface
            return error_response("Governance does not apply to this workflow's surface", :ungoverned_surface)
          end

          return error_response(
            "Unable to resolve governance rules for this workflow, please retry",
            :governance_resolution_failed
          )
        end

        @agent_privileges &= result.payload[:agent_privileges] if @agent_privileges

        clamp_pre_approved_privileges(result.payload[:pre_approved_agent_privileges])

        nil
      end

      # Clamps the values this update persists, taking the stored set for whichever
      # side the request omitted. That side is persisted too, so leaving it out of
      # the intersection lets a pre-approval predating the current rules survive.
      # Also re-applies the pre_approved subset invariant, which the model only
      # validates on create.
      def clamp_pre_approved_privileges(resolved_pre_approved)
        effective_privileges = @agent_privileges || @workflow.agent_privileges
        effective_pre_approved = @pre_approved_agent_privileges || @workflow.pre_approved_agent_privileges

        @pre_approved_agent_privileges =
          effective_pre_approved & resolved_pre_approved & effective_privileges
      end

      # `defined?`, not `||=`: nil is the common web result and must be cached too,
      # or background_surface repeats its query.
      def governance_surface
        return @governance_surface if defined?(@governance_surface)

        @governance_surface = ::Ai::ToolRules::GovernanceSurface.for(
          environment: @workflow.environment,
          container: governance_container,
          workflow_definition: @workflow.workflow_definition
        )
      end

      # Unrecognized environments (notably `external`) clamp against web rules.
      def resolution_service
        ::Ai::ToolRules::ResolutionService.new(
          namespace: governance_container.root_ancestor,
          surface: governance_surface || :web,
          project: @workflow.project
        )
      end

      def governance_container
        @workflow.project || @workflow.namespace
      end

      def update_agent_privileges
        @workflow.agent_privileges = @agent_privileges if @agent_privileges
        @workflow.pre_approved_agent_privileges = @pre_approved_agent_privileges if @pre_approved_agent_privileges

        if @workflow.save
          ServiceResponse.success(
            payload: { workflow: @workflow },
            message: "Agent privileges updated successfully"
          )
        else
          error_response("Failed to update agent privileges: #{@workflow.errors.full_messages.join(', ')}")
        end
      end

      def error_response(message, reason = :bad_request)
        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
