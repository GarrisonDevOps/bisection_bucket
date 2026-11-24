# frozen_string_literal: true

module Mcp
  module Tools
    module Milestones
      class ListService < Base::GraphqlService
        STATE_VALUES = ::Types::MilestoneStateEnum.values.keys.freeze

        register_version '0.1.0', {
          toolset: :core,
          description: 'List milestones in a GitLab project or group. Identify the project or group with ' \
            'exactly one of url, project_id, or group_id. Returns milestones of all states unless state is set.',
          annotations: {
            title: 'List milestones',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          },
          input_schema: {
            type: 'object',
            required: [],
            properties: {
              url: {
                type: 'string',
                description: 'GitLab URL of the project or group.'
              },
              project_id: {
                type: 'string',
                description: 'ID or full path of the project.'
              },
              group_id: {
                type: 'string',
                description: 'ID or full path of the group.'
              },
              state: {
                type: 'string',
                enum: STATE_VALUES,
                description: 'Filter milestones by state.'
              },
              search: {
                type: 'string',
                description: 'Search string to filter milestones by title.'
              },
              include_ancestors: {
                type: 'boolean',
                description: 'Include milestones from parent groups. For a project, includes milestones ' \
                  "from the project's parent group and its ancestors."
              },
              include_descendants: {
                type: 'boolean',
                description: 'Include milestones from subgroups and their projects. Applies only to a group.'
              },
              **Mcp::Tools::Concerns::CursorPagination.input_schema_params(items: 'milestones')
            }
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::Milestones::ListTool
        end

        def perform_v0_1_0(arguments)
          execute_graphql_tool(arguments)
        end
      end
    end
  end
end
