# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowPolicy < BasePolicy
      condition(:can_use_agentic_chat) do
        can?(:access_duo_agentic_chat, @subject.resource_parent)
      end

      condition(:can_use_duo_workflows_in_container) do
        can?(:duo_workflow, @subject.resource_parent)
      end

      condition(:client_executed_workflow) do
        @subject.executed_by_client?
      end

      condition(:can_use_client_executed_workflow) do
        client_executed_workflow? && can_use_agentic_chat?
      end

      condition(:can_use_duo_workflows_in_project) do
        can?(:duo_workflow, @subject.project)
      end

      condition(:is_workflow_owner) do
        @subject.invoked_by?(@user) ||
          @user&.composite_ai_service_account?
      end

      condition(:is_workflow_invoker) do
        @subject.invoked_by?(@user)
      end

      condition(:code_review_flow_on_updatable_merge_request) do
        next false unless @subject.workflow_definition ==
          ::Ai::Catalog::FoundationalFlow.code_review_v1.foundational_flow_reference

        merge_request = @subject.merge_request
        next false unless merge_request

        can?(:update_merge_request, merge_request)
      end

      condition(:can_update_workflow) do
        can?(:update_duo_workflow, @subject)
      end

      condition(:agentic_chat_workflow) do
        @subject.chat?
      end

      condition(:true_duo_workflow) do
        !@subject.chat?
      end

      condition(:duo_workflow_in_ci_available) do
        !!@subject.project&.duo_remote_flows_enabled
      end

      condition(:can_execute_workflow_in_ci) do
        can?(:execute_duo_workflow_in_ci)
      end

      condition(:foundational_agent_available) do
        agent = ::Ai::FoundationalChatAgent.with_workflow_definition(@subject.workflow_definition)
        next false unless @user && agent

        root = @subject.resource_parent.root_ancestor
        next false unless agent.licensed_for?(root)

        !!@user.duo_foundational_agents_container(root)&.foundational_agent_enabled?(agent.reference)
      end

      condition(:from_pipeline) do
        @subject.from_pipeline?
      end

      condition(:resumable) do
        @subject.resumable?
      end

      condition(:mcp_workhorse_session) do
        @subject.mcp_workhorse_session?
      end

      condition(:awaiting_input) do
        @subject.status_group == :awaiting_input
      end

      condition(:restartable) do
        @subject.restartable?
      end

      condition(:can_read_agent_artifacts_in_parent) do
        parent = @subject.resource_parent
        next false unless parent

        can?(:read_agent_artifacts, parent)
      end

      # `true_duo_workflow` uses `!chat?`, but `chat?` returns true for ALL
      # foundational agent sessions. This condition explicitly targets non-chat
      # agents so compliance reviewers can access them via the Agent Artifacts dashboard.
      condition(:foundational_agent_workflow) do
        agent = ::Ai::FoundationalChatAgent.with_workflow_definition(@subject.workflow_definition)
        agent.present? && !agent.duo_chat?
      end

      condition(:private_messaging_session) do
        @subject.private_messaging_session?
      end

      condition(:private_session_invoker) do
        @subject.invoked_by?(@user) || service_account_acting_for_invoker?
      end

      rule { true_duo_workflow & can_use_duo_workflows_in_project & from_pipeline }.policy do
        enable :read_duo_workflow
      end

      rule { true_duo_workflow & can_use_duo_workflows_in_container & is_workflow_owner }.policy do
        enable :read_duo_workflow
        enable :update_duo_workflow
        enable :resume_duo_workflow
        enable :restart_duo_workflow
      end

      rule { true_duo_workflow & can_use_client_executed_workflow & is_workflow_invoker }.policy do
        enable :read_duo_workflow
        enable :update_duo_workflow
      end

      rule { code_review_flow_on_updatable_merge_request }.enable :stop_duo_workflow

      rule { agentic_chat_workflow & can_use_agentic_chat & is_workflow_owner }.policy do
        enable :read_duo_workflow
        enable :update_duo_workflow
      end

      rule { agentic_chat_workflow & can_use_agentic_chat & is_workflow_owner & can_execute_workflow_in_ci }
        .enable :resume_duo_workflow

      rule { agentic_chat_workflow & ~foundational_agent_available }.prevent :execute_duo_workflow_in_ci

      rule { duo_workflow_in_ci_available & can_use_duo_workflows_in_project & can_update_workflow }.policy do
        enable :execute_duo_workflow_in_ci
      end

      # Limited to the session's own principal, since the resolved rules are otherwise readable only from
      # Maintainer up (read_ai_tool_rule).
      rule { can_update_workflow }.enable :read_duo_workflow_tool_access_policy

      rule do
        agentic_chat_workflow & mcp_workhorse_session & can_use_agentic_chat &
          foundational_agent_available & is_workflow_invoker
      end.enable :resume_duo_workflow

      rule { ~mcp_workhorse_session & ~resumable }.prevent :resume_duo_workflow
      rule { mcp_workhorse_session & ~awaiting_input }.prevent :resume_duo_workflow
      rule { mcp_workhorse_session & ~is_workflow_invoker }.prevent :resume_duo_workflow
      rule { ~restartable }.prevent :restart_duo_workflow

      rule { agentic_chat_workflow & is_workflow_owner }.enable :delete_duo_workflow

      # Compliance reviewers with :read_agent_artifacts on the workflow's
      # parent can read agent artifacts for non-chat workflows. :read_duo_workflow
      # is granted so the reviewer can reach the WorkflowType GraphQL node.
      # true_duo_workflow covers software_development and similar workflows.
      # foundational_agent_workflow covers security analyst, orbit, etc.
      # Chat sessions remain private to their owner.
      rule { true_duo_workflow & can_read_agent_artifacts_in_parent }.policy do
        enable :read_duo_workflow
        enable :read_agent_artifacts
      end

      rule { foundational_agent_workflow & can_read_agent_artifacts_in_parent }.policy do
        enable :read_duo_workflow
        enable :read_agent_artifacts
      end

      rule { private_messaging_session & ~private_session_invoker }.policy do
        prevent :read_duo_workflow
        prevent :read_agent_artifacts
        prevent :update_duo_workflow
        prevent :resume_duo_workflow
        prevent :restart_duo_workflow
        prevent :stop_duo_workflow
      end

      private

      def service_account_acting_for_invoker?
        return false unless @user&.composite_ai_service_account?

        identity = ::Gitlab::Auth::Identity.fabricate(@user)
        return false unless identity&.linked?

        @subject.invoked_by?(identity.scoped_user)
      end
    end
  end
end
