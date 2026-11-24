# frozen_string_literal: true

module Mcp
  module Tools
    module Groups
      class GetGroupService < Base::GraphqlService
        register_version '0.1.0', {
          toolset: :core,
          description: 'Get metadata for a single GitLab group: numeric ID, full path, name, visibility, ' \
            'parent, and web URL. Identify the group with exactly one of url or group_id. ' \
            'Use list_groups to discover groups.',
          input_schema: {
            type: 'object',
            required: [],
            properties: {
              url: {
                type: 'string',
                description: 'GitLab URL of the group.'
              },
              group_id: {
                type: 'string',
                description: 'Group ID or full path. Provide exactly one of url or group_id.'
              }
            }
          },
          annotations: {
            title: 'Get group',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::Groups::GetGroupTool
        end

        def perform_v0_1_0(arguments)
          execute_graphql_tool(arguments)
        end
      end
    end
  end
end
