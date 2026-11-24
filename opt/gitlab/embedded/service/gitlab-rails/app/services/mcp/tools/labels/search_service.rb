# frozen_string_literal: true

module Mcp
  module Tools
    module Labels
      class SearchService < Base::GraphqlService
        container_arguments project_or_group: :full_path

        register_version '0.1.0', {
          toolset: :core,
          description: 'Search labels in a GitLab project or group',
          annotations: {
            title: 'Search labels',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          },
          input_schema: {
            type: 'object',
            properties: {
              # Label search identification (one set required)
              full_path: {
                type: 'string',
                description: 'Full path of the project or group. Required.'
              },
              is_project: {
                type: 'boolean',
                description: 'Whether to search in a project (true) or group (false). Required.'
              },
              search: {
                type: 'string',
                description: 'Search term to filter labels by title.'
              }
            },
            required: %w[full_path is_project]
          }
        }

        register_version '0.2.0', {
          description: 'Search labels in a GitLab project or group by multiple terms',
          annotations: {
            title: 'Search labels',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          },
          toolset: :core,
          input_schema: {
            type: 'object',
            properties: {
              # Namespace identification (exactly one required)
              project_id: {
                type: 'string',
                description: 'ID or path of the project to search labels in. ' \
                  'Alternative to group_id or full_path.'
              },
              group_id: {
                type: 'string',
                description: 'ID or path of the group to search labels in. ' \
                  'Alternative to project_id or full_path.'
              },
              full_path: {
                type: 'string',
                description: 'Full path of the project or group. Alternative to project_id or group_id. ' \
                  'Requires is_project.'
              },
              is_project: {
                type: 'boolean',
                description: 'Whether full_path is a project (true) or group (false). Required with full_path.'
              },
              search: {
                oneOf: [
                  { type: 'string' },
                  { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 10 }
                ],
                description: 'Search term, or up to 10 terms, to filter labels by title. Omit to list labels.'
              }
            }
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::Labels::SearchTool
        end

        def perform_v0_1_0(arguments)
          execute_graphql_tool(arguments)
        end

        def perform_v0_2_0(arguments)
          execute_graphql_tool(arguments)
        end

        override :perform_default
        def perform_default(arguments = {})
          perform_v0_2_0(arguments)
        end
      end
    end
  end
end
