# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class GenerateAgentConfigService
      GOAL_EVENT_TYPE = :init_execution_env
      LEASE_TTL = 2.minutes

      NO_PERMISSION_ERROR = 'You have insufficient permissions'
      ALREADY_PRESENT_ERROR = 'The agent configuration file already exists.'
      ALREADY_RUNNING_ERROR = 'An agent configuration run is already in progress.'

      def initialize(project:, current_user:)
        @project = project
        @current_user = current_user
      end

      def execute
        return error(NO_PERMISSION_ERROR) unless Ability.allowed?(current_user, :duo_workflow, project)
        return error(ALREADY_PRESENT_ERROR) if agent_config_present?

        active_workflow = tracker.active_workflow
        return error(ALREADY_RUNNING_ERROR, payload: { workflow_id: active_workflow.id }) if active_workflow

        start_workflow
      end

      private

      attr_reader :project, :current_user

      def start_workflow
        lease_uuid = Gitlab::ExclusiveLease.new(lease_key, timeout: LEASE_TTL.to_i).try_obtain
        return error(ALREADY_RUNNING_ERROR) unless lease_uuid

        begin
          result = execute_flow

          return error(Array(result.message).first) unless result.success?

          workflow = result.payload[:workflow]
          tracker.track(workflow)

          ServiceResponse.success(payload: { workflow_id: workflow.id })
        ensure
          Gitlab::ExclusiveLease.cancel(lease_key, lease_uuid)
        end
      end

      def execute_flow
        consumer = developer_flow_consumer

        ::Ai::Catalog::Flows::ExecuteService.new(
          project: project,
          current_user: current_user,
          params: {
            item_consumer: consumer,
            user_prompt: goal,
            event_type: 'web',
            execute_workflow: true,
            service_account: consumer&.active_service_account
          }
        ).execute
      end

      def goal
        ::Ai::Catalog::GoalTemplates::Developer.resolve(
          event_type: GOAL_EVENT_TYPE,
          resource: project,
          user_input: nil,
          params: { triggered_by_username: current_user.username }
        )
      end

      def developer_flow_consumer
        catalog_item = ::Ai::Catalog::FoundationalFlow.developer_v1.catalog_item

        catalog_item&.consumers&.for_projects(project)&.first
      end

      def agent_config_present?
        ::Gitlab::DuoAgentPlatform::Config.new(project).config_present?
      end

      def tracker
        @tracker ||= ::Ai::DuoWorkflow::AgentConfigWorkflowTracker.new(project)
      end

      def lease_key
        "duo_agent_config_generation:#{project.id}"
      end

      def error(message, payload: {})
        ServiceResponse.error(message: message, payload: payload)
      end
    end
  end
end
