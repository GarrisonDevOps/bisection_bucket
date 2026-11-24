# frozen_string_literal: true

module Mcp
  module Tools
    module WorkItems
      class ListSavedViewsTool < BaseTool
        include Mcp::Tools::Concerns::CursorPagination

        register_version VERSIONS[:v0_1_0], {
          operation_name: 'namespace',
          graphql_operation: load_graphql('work_items/list_saved_views.query.graphql')
        }

        def build_variables
          ensure_single_parent_identifier!
          ensure_relative_position_is_subscribed!

          {
            fullPath: resolve_parent[:full_path],
            search: params[:search],
            subscribedOnly: params[:subscribed_only],
            sort: params[:sort],
            **resolve_pagination_direction
          }.compact
        end

        private

        def ensure_single_parent_identifier!
          given = [:url, :project_id, :group_id].select { |key| params[key].present? }
          return if given.length <= 1

          raise ArgumentError, "Provide exactly one of url, project_id, or group_id (got #{given.join(', ')})"
        end

        def ensure_relative_position_is_subscribed!
          return unless params[:sort] == 'RELATIVE_POSITION' && !params[:subscribed_only]

          raise ArgumentError, 'sort RELATIVE_POSITION requires subscribed_only: true'
        end

        def process_result(result)
          processed = super
          return processed if processed[:isError]

          connection = processed[:structuredContent]['savedViews']
          return resource_not_found_error unless connection

          connection['nodes'].each do |node|
            node['id'] = ::GlobalID.parse(node['id']).model_id.to_i
          end

          structured_content = {
            'saved_views' => connection['nodes'],
            'pageInfo' => connection['pageInfo']
          }

          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(structured_content) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, structured_content)
        end

        def resource_not_found_error
          ::Mcp::Tools::Base::Response.error(
            'Project or group not found: it does not exist or you do not have access to it.',
            reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND
          )
        end
      end
    end
  end
end
