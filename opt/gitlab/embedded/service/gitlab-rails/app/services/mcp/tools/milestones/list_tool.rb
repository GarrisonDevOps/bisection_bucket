# frozen_string_literal: true

module Mcp
  module Tools
    module Milestones
      class ListTool < Mcp::Tools::Base::GraphqlTool
        include Mcp::Tools::Concerns::ResourceFinder
        include Mcp::Tools::Concerns::UrlParser
        include Mcp::Tools::Concerns::CursorPagination

        PARENT_PARAMS = %i[url project_id group_id].freeze

        register_version VERSIONS[:v0_1_0], {
          graphql_operation: load_graphql('milestones/list_milestones.query.graphql')
        }

        def build_variables
          parent = resolved_parent

          {
            fullPath: parent[:full_path],
            isProject: parent[:type] == :project,
            state: params[:state],
            searchTitle: params[:search],
            includeAncestors: params[:include_ancestors],
            includeDescendants: params[:include_descendants],
            **resolve_pagination_direction
          }.compact
        end

        # The response field depends on whether the parent is a project or group.
        def operation_name
          resolved_parent[:type].to_s
        end

        private

        def resolved_parent
          @resolved_parent ||= resolve_parent
        end

        def resolve_parent
          provided = PARENT_PARAMS.select { |key| params[key].present? }

          raise ArgumentError, 'Provide exactly one of: url, project_id, or group_id' unless provided.one?

          type, identifier = parent_type_and_identifier(provided.first)
          parent = find_parent_by_id_or_path!(type, identifier)

          { type: type, full_path: parent.full_path }
        end

        def parent_type_and_identifier(provided_param)
          case provided_param
          when :url
            parsed = parse_parent_url(params[:url])
            [parsed[:type], parsed[:path]]
          when :project_id
            [:project, params[:project_id]]
          else
            [:group, params[:group_id]]
          end
        end

        def process_result(result)
          processed_result = super
          return processed_result if processed_result[:isError]

          milestones = processed_result[:structuredContent]['milestones']
          return resource_not_found_error unless milestones

          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(milestones) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, milestones)
        end

        def resource_not_found_error
          ::Mcp::Tools::Base::Response.error(
            "#{resolved_parent[:type].to_s.capitalize} not found or inaccessible",
            reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND
          )
        end
      end
    end
  end
end
