# frozen_string_literal: true

module EE
  module Types
    module Namespaces
      module LinkPaths
        module ProjectNamespaceLinksType
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          def epics_list
            return unless group

            url_helpers.group_epics_path(group)
          end

          def group_issues
            return unless group

            url_helpers.issues_group_path(group)
          end

          def labels_fetch
            url_helpers.project_labels_path(
              project,
              format: :json,
              only_group_labels: true,
              include_ancestor_groups: true
            )
          end
        end
      end
    end
  end
end
