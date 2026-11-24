# frozen_string_literal: true

module Mcp
  module Tools
    module Projects
      class GetProjectService < Base::GraphqlService
        register_version '0.1.0', {
          toolset: :core,
          description: 'Get metadata for a single GitLab project: numeric ID, full path, default ' \
            'branch, visibility, and web URL. Identify the project with exactly one of url or ' \
            'project_id. Use search with scope projects to find a project you cannot name yet. ' \
            'Pass include: ["work_item_types"] to also return the project work item types and ' \
            'their enabled widgets, for use before save_work_item.',
          input_schema: {
            type: 'object',
            required: [],
            properties: {
              url: {
                type: 'string',
                description: 'GitLab URL of the project.'
              },
              project_id: {
                type: 'string',
                description: 'Project ID or full path. Provide exactly one of url or project_id.'
              },
              include: {
                type: 'array',
                description: 'Facet to include alongside the project, one per call: work_item_types.',
                items: {
                  type: 'string',
                  enum: GetProjectTool::FACETS.values
                },
                maxItems: 1
              }
            }
          },
          annotations: {
            title: 'Get project',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::Projects::GetProjectTool
        end

        def perform_v0_1_0(arguments)
          execute_graphql_tool(arguments)
        end

        override :perform_default
        def perform_default(arguments = {})
          perform_v0_1_0(arguments)
        end
      end
    end
  end
end
