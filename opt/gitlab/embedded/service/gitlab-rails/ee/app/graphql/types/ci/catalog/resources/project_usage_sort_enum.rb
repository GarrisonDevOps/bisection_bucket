# frozen_string_literal: true

module Types
  module Ci
    module Catalog
      module Resources
        class ProjectUsageSortEnum < BaseEnum
          graphql_name 'CiCatalogResourceProjectUsageSort'
          description 'Values for sorting projects that use components from a catalog resource.'

          value 'OLDEST_VERSION_ASC', 'Oldest version a project uses by ascending order.',
            value: :oldest_version_asc
          value 'OLDEST_VERSION_DESC', 'Oldest version a project uses by descending order.',
            value: :oldest_version_desc
          value 'VERSION_ASC', 'Newest version a project uses by ascending order.',
            value: :version_asc
          value 'VERSION_DESC', 'Newest version a project uses by descending order.',
            value: :version_desc
          value 'LAST_USED_ASC', 'Last used date by ascending order.',
            value: :last_used_asc
          value 'LAST_USED_DESC', 'Last used date by descending order.',
            value: :last_used_desc
          value 'PROJECT_NAME_ASC', 'Project name by ascending order.',
            value: :project_name_asc
          value 'PROJECT_NAME_DESC', 'Project name by descending order.',
            value: :project_name_desc
        end
      end
    end
  end
end
