# frozen_string_literal: true

module Ai
  module ToolRules
    class McpCallerSurface
      include ::Gitlab::Utils::StrongMemoize

      def self.for(access_token, user)
        new(access_token, user).surface
      end

      def initialize(access_token, user)
        @access_token = access_token
        @user = user
      end

      def surface
        return ::Ai::ToolRules::GovernanceSurface::LOCAL unless ::Ai::DuoWorkflows::WorkflowTokenScope.bound?(scopes)
        return workflow_surface if workflow

        log_refusal
        ::Ai::ToolRules::GovernanceSurface::REFUSED
      end

      private

      attr_reader :access_token, :user

      def scopes
        access_token.respond_to?(:scopes) ? access_token.scopes : []
      end

      def workflow_id
        ::Ai::DuoWorkflows::WorkflowTokenScope.workflow_id_from(scopes)
      end
      strong_memoize_attr :workflow_id

      def bound_workflow
        ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id) if workflow_id
      end
      strong_memoize_attr :bound_workflow

      def workflow
        bound_workflow if bound_workflow && ::Ability.allowed?(user, :read_duo_workflow, bound_workflow)
      end
      strong_memoize_attr :workflow

      def workflow_surface
        surface = ::Ai::ToolRules::GovernanceSurface.for(
          environment: workflow.environment,
          container: workflow.resource_parent,
          workflow_definition: workflow.workflow_definition
        )
        return surface if surface == ::Ai::ToolRules::GovernanceSurface::BACKGROUND

        workflow.environment&.to_sym || ::Ai::ToolRules::GovernanceSurface::LOCAL
      end

      def refusal_reason
        return 'invalid_workflow_scope' unless workflow_id
        return 'workflow_not_found' unless bound_workflow

        'workflow_not_readable'
      end

      def log_refusal
        ::Gitlab::Mcp::Logger.build.conditional_info(
          user,
          message: 'MCP session refused',
          event_name: 'session_refused',
          ai_component: 'mcp_server',
          ::Labkit::Fields::DUO_WORKFLOW_ID => workflow_id,
          refusal_reason: refusal_reason
        )
      end
    end
  end
end
