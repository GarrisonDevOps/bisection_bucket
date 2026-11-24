# frozen_string_literal: true

module Mcp
  module Tools
    module Security
      class AttachScanProfileTool < Mcp::Tools::Base::GraphqlTool
        include ::Gitlab::ResourceLookup

        register_version '0.1.0', {
          operation_name: 'securityScanProfileAttach',
          graphql_operation: load_graphql('security/attach_scan_profile.query.graphql')
        }

        def build_variables
          {
            input: {
              securityScanProfileId: params[:security_scan_profile_id],
              projectIds: resolved_global_ids(::Project, params[:project_ids]) { |ids| lookup_projects(ids) },
              groupIds: resolved_global_ids(::Group, params[:group_ids]) { |ids| lookup_groups(ids) }
            }
          }
        end

        private

        def resolved_global_ids(model, ids)
          model_ids = ids.to_a.index_with { |id| model_id_for(id, model) }
          found = yield(model_ids.values.compact).index_by { |container| container.id.to_s }

          model_ids.map do |id, model_id|
            container = found[model_id.to_s]
            raise ::Mcp::Tools::Concerns::ResourceFinder::ResourceNotFoundError, not_found_message(id) unless container

            container.to_global_id.to_s
          end
        end

        def model_id_for(id, model)
          global_id = ::GlobalID.parse(::Mcp::Tools::Concerns::UrlParser.unescape_and_scrub_uri(id.to_s))
          global_id.model_id if global_id && global_id.model_class <= model
        rescue NameError
          nil
        end

        def not_found_message(id)
          "'#{id}' not found or inaccessible"
        end
      end
    end
  end
end
