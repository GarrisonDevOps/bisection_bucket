# frozen_string_literal: true

module Mcp
  module Tools
    module Projects
      class GetProjectTool < Mcp::Tools::Base::GraphqlTool
        include Mcp::Tools::Concerns::ResourceFinder
        include Mcp::Tools::Concerns::UrlParser

        PARENT_PARAMS = %i[url project_id].freeze
        FACETS = { includeWorkItemTypes: 'work_item_types' }.freeze

        register_version VERSIONS[:v0_1_0], {
          graphql_operation: load_graphql('projects/get_project.query.graphql'),
          operation_name: 'project'
        }

        def build_variables
          facets = Array(params[:include]).map(&:to_s)

          FACETS.transform_values { |facet| facets.include?(facet) }.merge(fullPath: resolve_project.full_path)
        end

        private

        def resolve_project
          provided = PARENT_PARAMS.select { |key| params[key].present? }

          raise ArgumentError, 'Provide exactly one of: url or project_id' unless provided.one?

          identifier = provided.first == :url ? parse_parent_url(params[:url])[:path] : params[:project_id]

          find_project!(identifier)
        end

        def process_result(result)
          processed_result = super
          return processed_result if processed_result[:isError]

          data = project_data(processed_result[:structuredContent])
          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(data) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, data)
        end

        def project_data(project)
          data = {
            id: ::GlobalID.parse(project['id']).model_id.to_i,
            path_with_namespace: project['fullPath'],
            # rootRef is null while the project has no repository yet.
            default_branch: project.dig('repository', 'rootRef'),
            visibility: project['visibility'],
            web_url: project['webUrl']
          }

          if project['workItemTypes']
            data[:work_item_types] = project['workItemTypes']['nodes'].map { |type| work_item_type_data(type) }
          end

          data
        end

        def work_item_type_data(type)
          {
            id: type['id'],
            name: type['name'],
            icon_name: type['iconName'],
            # rubocop:disable Rails/Pluck -- widgetDefinitions is a plain Array of Hashes, not an ActiveRecord relation
            widget_types: type['widgetDefinitions'].map { |widget| widget['type'] }
            # rubocop:enable Rails/Pluck
          }
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
