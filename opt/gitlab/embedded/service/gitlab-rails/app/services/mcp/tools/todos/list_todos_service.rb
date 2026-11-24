# frozen_string_literal: true

module Mcp
  module Tools
    module Todos
      class ListTodosService < Base::GraphqlService
        STATE_VALUES = ::Types::TodoStateEnum.values.keys.freeze
        ACTION_VALUES = ::Types::TodoActionEnum.values.keys.freeze
        TYPE_VALUES = ::Types::TodoTargetEnum.values.keys.freeze

        register_version '0.1.0', {
          toolset: :core,
          description: 'List the to-do items of the authenticated user, such as review requests, ' \
            'assignments, and mentions. Returns pending to-do items unless state is set. Each to-do ' \
            'item includes its numeric id, action, target type, target URL, and the name and iid ' \
            'of its target.',
          input_schema: {
            type: 'object',
            required: [],
            properties: {
              state: {
                type: 'string',
                enum: STATE_VALUES,
                description: 'Filter by state.'
              },
              action: {
                type: 'string',
                enum: ACTION_VALUES,
                description: 'Filter by the action that created the to-do item, for example ' \
                  'review_requested. A mention is mentioned, or directly_addressed when the ' \
                  'mention starts a paragraph.'
              },
              type: {
                type: 'string',
                enum: TYPE_VALUES,
                description: 'Filter by the type of the to-do item target, for example MERGEREQUEST or ISSUE.'
              },
              author_id: {
                type: 'integer',
                description: 'Filter by the numeric ID of the user who created the to-do item. ' \
                  'Use get_user to look up the ID of a username.'
              },
              project_id: {
                type: 'string',
                description: 'Filter by project. ID or full path of the project.'
              },
              group_id: {
                type: 'string',
                description: 'Filter by group. ID or full path of the group.'
              },
              **Mcp::Tools::Concerns::CursorPagination.input_schema_params(items: 'to-do items')
            }
          },
          annotations: {
            title: 'List to-do items',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::Todos::ListTodosTool
        end

        def perform_v0_1_0(arguments)
          execute_graphql_tool(arguments)
        end
      end
    end
  end
end
