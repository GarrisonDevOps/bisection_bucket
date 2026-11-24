# frozen_string_literal: true

module EE
  module Types
    module Namespaces
      module LinkPaths
        module GroupNamespaceLinksType
          extend ActiveSupport::Concern

          def epics_list
            url_helpers.group_epics_path(group)
          end

          def group_issues
            url_helpers.issues_group_path(group)
          end

          def labels_fetch
            url_helpers.group_labels_path(
              group,
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
