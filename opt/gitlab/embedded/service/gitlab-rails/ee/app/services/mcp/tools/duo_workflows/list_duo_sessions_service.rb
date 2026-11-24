# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      class ListDuoSessionsService < Base::GraphqlService
        include Availability

        STATUS_GROUPS = ::Ai::DuoWorkflows::Workflow::GROUPED_STATUSES.keys.map(&:to_s).freeze
        STATUSES = ::Ai::DuoWorkflows::Workflow.state_machine.states.map { |state| state.name.to_s }.freeze

        register_version '0.1.0', {
          toolset: :duo_agent_platform,
          description: 'List the authenticated user\'s Duo Agent Platform sessions, excluding Duo Chat sessions, ' \
            'optionally filtered by project, status group, or exact statuses, with compact metadata including a ' \
            'possibly truncated goal preview and cursor pagination.',
          input_schema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'GitLab URL of the project to filter sessions by.'
              },
              project_id: {
                type: 'string',
                description: 'Numeric ID or full path of the project to filter sessions by.'
              },
              status_group: {
                type: 'string',
                description: 'Filter by session status group.',
                enum: STATUS_GROUPS
              },
              statuses: {
                type: 'array',
                description: 'Filter by exact session statuses, for example the two approval states a session ' \
                  'can be parked on. Cannot be combined with status_group.',
                items: {
                  type: 'string',
                  enum: STATUSES
                },
                maxItems: STATUSES.size
              },
              **Mcp::Tools::Concerns::CursorPagination.input_schema_params(items: 'sessions')
            },
            required: []
          },
          annotations: {
            title: 'List Duo sessions',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        protected

        override :perform_default
        def perform_default(arguments = {})
          execute_graphql_tool(arguments)
        end

        private

        def graphql_tool_class
          Mcp::Tools::DuoWorkflows::ListDuoSessionsTool
        end
      end
    end
  end
end
