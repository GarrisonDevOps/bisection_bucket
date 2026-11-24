# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class GroupItemEnabledByEnum < BaseEnum
        graphql_name 'AiCatalogGroupItemEnabledBy'
        description 'Ways an AI Catalog item can be enabled in a group.'

        value 'INHERITANCE',
          value: 'inheritance',
          description: 'Enabled for all projects in the group through group inheritance. ' \
            'Only top-level groups can enable items this way. ' \
            'Matches no items unless the `ai_catalog_group_inherited_consumers` feature flag is enabled.'

        value 'PROJECT_DIRECT',
          value: 'project_direct',
          description: 'Enabled directly in at least one project in the group, including projects in subgroups. ' \
            'Only top-level groups can match, and project configurations that are not linked to a group ' \
            'configuration of the item are not included.'

        value 'NONE',
          value: 'none',
          description: 'Not enabled in any of the other ways.'
      end
    end
  end
end
