# frozen_string_literal: true

module Mcp
  module Tools
    module Security
      class ListVulnerabilitiesTool < Mcp::Tools::Base::GraphqlTool
        include Mcp::Tools::Concerns::CursorPagination
        include Mcp::Tools::Concerns::ResourceFinder

        register_version VERSIONS[:v0_1_0], {
          operation_name: 'project',
          graphql_operation: load_graphql('security/list_vulnerabilities.query.graphql')
        }

        def execute
          return resource_not_found_error unless project

          super
        end

        protected

        def build_variables_v0_1_0
          {
            fullPath: project.full_path,
            severity: params[:severity].presence,
            reportType: params[:report_type].presence,
            state: params[:state].presence,
            first: paginated_first,
            after: params[:after]
          }.compact
        end

        private

        def project
          @project ||= find_project(params[:project_full_path].to_s)
        end

        def process_result(result)
          processed_result = super
          return processed_result if processed_result[:isError]

          vulnerabilities = processed_result[:structuredContent]['vulnerabilities']
          return ::Mcp::Tools::Base::Response.error('Operation returned no data') unless vulnerabilities

          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(vulnerabilities) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, vulnerabilities)
        end

        def resource_not_found_error
          ::Mcp::Tools::Base::Response.error(
            'Project not found: it does not exist or you do not have access to it.',
            reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND
          )
        end
      end
    end
  end
end
