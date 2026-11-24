# frozen_string_literal: true

module Mcp
  module Tools
    module Groups
      class GetGroupTool < Mcp::Tools::Base::GraphqlTool
        include Mcp::Tools::Concerns::ResourceFinder
        include Mcp::Tools::Concerns::UrlParser

        PARENT_PARAMS = %i[url group_id].freeze

        register_version VERSIONS[:v0_1_0], {
          graphql_operation: load_graphql('groups/get_group.query.graphql'),
          operation_name: 'group'
        }

        def build_variables
          { fullPath: resolve_group.full_path }
        end

        private

        def resolve_group
          provided = PARENT_PARAMS.select { |key| params[key].present? }

          raise ArgumentError, 'Provide exactly one of: url or group_id' unless provided.one?

          identifier = provided.first == :url ? parse_parent_url(params[:url])[:path] : params[:group_id]

          find_group!(identifier)
        end

        def process_result(result)
          processed_result = super
          return processed_result if processed_result[:isError]

          group = processed_result[:structuredContent]
          group['id'] = ::GlobalID.parse(group['id']).model_id.to_i
          group['parent']['id'] = ::GlobalID.parse(group['parent']['id']).model_id.to_i if group['parent']

          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(group) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, group)
        end

        def resource_not_found_error
          ::Mcp::Tools::Base::Response.error(
            'Group not found: it does not exist or you do not have access to it.',
            reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND
          )
        end
      end
    end
  end
end
