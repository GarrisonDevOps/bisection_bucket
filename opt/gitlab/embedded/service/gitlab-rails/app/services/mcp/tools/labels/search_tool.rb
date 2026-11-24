# frozen_string_literal: true

module Mcp
  module Tools
    module Labels
      class SearchTool < Mcp::Tools::Base::GraphqlTool
        include Mcp::Tools::Concerns::ResourceFinder

        register_version VERSIONS[:v0_1_0], {
          graphql_operation: load_graphql('labels/search.v0_1_0.query.graphql')
        }

        register_version '0.2.0', {
          graphql_operation: load_graphql('labels/search.v0_2_0.query.graphql')
        }

        def execute
          validate_identifiers! unless version == VERSIONS[:v0_1_0]
          return resource_not_found_error unless target
          return super if version == VERSIONS[:v0_1_0] || !params[:search].is_a?(Array)

          labels = []
          result = nil

          Array(params[:search]).uniq.each do |term|
            result = self.class.new(
              current_user: current_user,
              params: params.merge(search: term),
              version: version,
              access_token: access_token,
              request: request
            ).execute

            break if result[:isError]

            labels.concat(result[:structuredContent][:items])
          end

          return result if result[:isError]

          labels.uniq! { |label| label['id'] }

          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(labels) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, labels)
        end

        def build_variables
          {
            isProject: project_request?,
            fullPath: target.full_path,
            search: params[:search]
          }.compact
        end

        def operation_name
          project_request? ? 'project' : 'group'
        end

        private

        def project_request?
          return true if params[:project_id].present?
          return false if params[:group_id].present?

          params[:is_project]
        end

        def target
          @target ||= if params[:project_id].present?
                        find_project(params[:project_id].to_s)
                      elsif params[:group_id].present?
                        find_group(params[:group_id].to_s)
                      else
                        params[:is_project] ? find_project(params[:full_path].to_s) : find_group(params[:full_path])
                      end
        end

        def identifiers_given
          %i[project_id group_id full_path].select { |key| params[key].present? }
        end

        def validate_identifiers!
          given = identifiers_given
          raise ArgumentError, 'Provide exactly one of project_id, group_id, or full_path' unless given.one?
          raise ArgumentError, 'full_path requires is_project' if given == [:full_path] && params[:is_project].nil?
        end

        def process_result(result)
          processed_result = super

          return processed_result if processed_result[:isError]

          labels = extract_labels(processed_result[:structuredContent])
          return ::Mcp::Tools::Base::Response.error("Operation returned no data") unless labels

          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(labels) }]
          ::Mcp::Tools::Base::Response.success(formatted_content, labels)
        end

        def extract_labels(structured_content)
          structured_content&.dig('labels', 'nodes')
        end

        def resource_not_found_error
          resource_type = project_request? ? 'Project' : 'Group'
          identifier = params[:project_id].presence || params[:group_id].presence || params[:full_path]
          message = "#{resource_type} '#{identifier}' not found or inaccessible"
          ::Mcp::Tools::Base::Response.error(message, reason: ::Mcp::Tools::Base::Response::Reason::NOT_FOUND)
        end
      end
    end
  end
end
