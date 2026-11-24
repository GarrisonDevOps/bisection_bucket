# frozen_string_literal: true

module Mcp
  module Tools
    module WorkItems
      class ListSavedViewsService < Base::GraphqlService
        SORT_VALUES = %w[ID NAME_ASC RELATIVE_POSITION].freeze

        register_version '0.1.0', {
          toolset: :work_items,
          description: 'List the work item saved views in a project or group. Provide exactly one of url, ' \
            'project_id, or group_id. Each row carries the saved view ID, name, description, sort, ' \
            'visibility, and whether the current user is subscribed. Pass the ID to get_saved_view_work_items ' \
            'for the filters and work items of one saved view.',
          input_schema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'GitLab URL for the project or group.'
              },
              group_id: {
                type: 'string',
                description: 'ID or path of the group.'
              },
              project_id: {
                type: 'string',
                description: 'ID or path of the project.'
              },
              search: {
                type: 'string',
                description: 'Search saved views by name or description.'
              },
              subscribed_only: {
                type: 'boolean',
                description: 'Return only saved views the current user is subscribed to.'
              },
              sort: {
                type: 'string',
                enum: SORT_VALUES,
                description: 'Sort order. ID sorts newest first, NAME_ASC sorts by name. RELATIVE_POSITION sorts ' \
                  'by your order of subscribed views and requires subscribed_only: true. Sorted by ID unless set.'
              },
              **Mcp::Tools::Concerns::CursorPagination.input_schema_params(items: 'saved views')
            },
            required: []
          },
          annotations: {
            title: 'List work item saved views',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        protected

        def graphql_tool_class
          Mcp::Tools::WorkItems::ListSavedViewsTool
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
