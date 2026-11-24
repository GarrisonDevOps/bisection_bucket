# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      class ListDuoSessionsTool < Mcp::Tools::Base::GraphqlTool
        include Mcp::Tools::Concerns::ResourceFinder
        include Mcp::Tools::Concerns::UrlParser
        include Mcp::Tools::Concerns::CursorPagination

        PARENT_PARAMS = %i[url project_id].freeze
        GOAL_PREVIEW_LIMIT = 160

        register_version VERSIONS[:v0_1_0], {
          graphql_operation: load_graphql('duo_workflows/list_duo_sessions.query.graphql'),
          operation_name: 'duoWorkflowWorkflows'
        }

        def build_variables
          reject_conflicting_status_filters!

          {
            projectPath: project_full_path,
            # MCP exposes lowercase status names; GraphQL expects their uppercase enum names.
            statusGroup: params[:status_group]&.upcase,
            statuses: params[:statuses]&.map(&:upcase),
            excludeTypes: ::Ai::FoundationalChatAgent.only_duo_chat_agent.map(&:workflow_definition),
            **resolve_pagination_direction
          }.compact
        end

        private

        def reject_conflicting_status_filters!
          return if params[:status_group].nil? || params[:statuses].nil?

          raise ArgumentError, 'Provide at most one of: status_group or statuses'
        end

        def project_full_path
          return unless project_filter?

          resolve_project.full_path
        end

        def project_filter?
          PARENT_PARAMS.any? { |param| params[param].present? }
        end

        def resolve_project
          provided = PARENT_PARAMS.select { |param| params[param].present? }

          raise ArgumentError, 'Provide at most one of: url or project_id' unless provided.one?

          identifier = provided.first == :url ? parse_parent_url(params[:url])[:path] : params[:project_id]

          find_parent_by_id_or_path!(:project, identifier)
        end

        def process_result(result)
          processed_result = super
          return processed_result if processed_result[:isError]

          connection = processed_result[:structuredContent]
          sessions = connection['nodes']
          page_info = connection['pageInfo']
          return ::Mcp::Tools::Base::Response.error('Operation returned no data') unless sessions && page_info

          data = {
            'sessions' => sessions.map { |session| session_data(session) },
            'pageInfo' => page_info
          }
          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(data) }]

          ::Mcp::Tools::Base::Response.success(formatted_content, data)
        end

        def session_data(session)
          {
            'id' => session.fetch('id').split('/').last.to_i,
            'status' => session['statusName'],
            'goal' => session['goal']&.truncate(GOAL_PREVIEW_LIMIT),
            'flow' => session['workflowDefinition'],
            'web_url' => session['webUrl'],
            'created_at' => session['createdAt']
          }
        end
      end
    end
  end
end
