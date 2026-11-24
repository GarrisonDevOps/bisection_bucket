# frozen_string_literal: true

module Mcp
  module Tools
    module Todos
      class ListTodosTool < Mcp::Tools::Base::GraphqlTool
        include Mcp::Tools::Concerns::ResourceFinder
        include Mcp::Tools::Concerns::CursorPagination

        register_version VERSIONS[:v0_1_0], {
          operation_name: 'currentUser',
          graphql_operation: load_graphql('todos/list_todos.query.graphql')
        }

        def build_variables
          {
            state: Array.wrap(params[:state]).presence,
            action: Array.wrap(params[:action]).presence,
            type: Array.wrap(params[:type]).presence,
            authorId: Array.wrap(params[:author_id]&.to_s).presence,
            projectId: project_ids,
            groupId: group_ids,
            **resolve_pagination_direction
          }.compact
        end

        private

        # The todos connection filters by numeric ID only, so resolve a full path here.
        def project_ids
          return if params[:project_id].blank?

          [find_project!(params[:project_id]).id.to_s]
        end

        def group_ids
          return if params[:group_id].blank?

          [find_group!(params[:group_id]).id.to_s]
        end

        def process_result(result)
          processed_result = super
          return processed_result if processed_result[:isError]

          todos = processed_result[:structuredContent]['todos']
          todos['nodes'].each { |todo| unwrap_ids(todo) }

          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(todos) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, todos)
        end

        # To-dos, authors, projects, and groups are addressed by their global numeric ID, so unwrap the
        # GIDs to let the output chain back into tool inputs such as author_id, project_id and group_id.
        def unwrap_ids(todo)
          todo['id'] = numeric_id(todo['id'])
          todo['author']['id'] = numeric_id(todo['author']['id'])
          todo['project']['id'] = numeric_id(todo['project']['id']) if todo['project']
          todo['group']['id'] = numeric_id(todo['group']['id']) if todo['group']
        end

        def numeric_id(gid)
          ::GlobalID.parse(gid).model_id.to_i
        end
      end
    end
  end
end
