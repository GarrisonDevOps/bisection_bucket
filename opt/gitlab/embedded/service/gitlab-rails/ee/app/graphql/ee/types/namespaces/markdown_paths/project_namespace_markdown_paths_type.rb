# frozen_string_literal: true

module EE
  module Types
    module Namespaces
      module MarkdownPaths
        module ProjectNamespaceMarkdownPathsType
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          override :autocomplete_sources_path
          def autocomplete_sources_path(iid: nil, work_item_type_id: nil)
            paths = super

            params = build_autocomplete_params(iid: iid, work_item_type_id: work_item_type_id)

            if project.licensed_feature_available?(:epics)
              paths[:epics] = url_helpers.epics_project_autocomplete_sources_path(project, params)
            end

            if project.licensed_feature_available?(:iterations)
              paths[:iterations] = url_helpers.iterations_project_autocomplete_sources_path(project, params)
            end

            if project.licensed_feature_available?(:security_dashboard)
              paths[:vulnerabilities] = url_helpers.vulnerabilities_project_autocomplete_sources_path(project, params)
            end

            paths.freeze
          end
        end
      end
    end
  end
end
