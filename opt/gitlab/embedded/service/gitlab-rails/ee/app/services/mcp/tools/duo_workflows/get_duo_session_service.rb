# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      class GetDuoSessionService < Base::GraphqlService
        include Availability

        container_arguments record: { workflow_id: ->(id) { container_from_workflow(id) } }

        register_version '0.1.0', {
          toolset: :duo_agent_platform,
          description: 'Check a Duo Agent Platform session started by start_duo_session. ' \
            'Running sessions include a poll_after_seconds hint. Finished and input-required sessions include ' \
            'the latest agent answer. Any merge request, work item or comment the session created is included ' \
            'once it exists. Failed sessions include the recorded failure_reason and the job_url of their CI job. ' \
            'Approval-required sessions need send_duo_session_input instead of polling.',
          input_schema: {
            type: 'object',
            properties: {
              workflow_id: {
                type: 'integer',
                description: 'ID of the Duo session, as returned by start_duo_session or list_duo_sessions.'
              }
            },
            required: %w[workflow_id]
          },
          annotations: {
            title: 'Get Duo session',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        override :tool_aliases
        def self.tool_aliases
          ['get_duo_workflow_status']
        end

        protected

        def container_from_workflow(id)
          workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(id)

          workflow&.project || workflow&.namespace
        end

        override :perform_default
        def perform_default(arguments = {})
          execute_graphql_tool(arguments)
        end

        private

        def graphql_tool_class
          Mcp::Tools::DuoWorkflows::GetDuoSessionTool
        end
      end
    end
  end
end
