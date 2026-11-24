# frozen_string_literal: true

module Types
  module Analytics
    module Dashboards
      class GridHeightEnum < BaseEnum
        graphql_name 'CustomizableDashboardGridHeight'
        description 'Grid heights for customizable dashboards.'

        value 'DEFAULT', value: 'default',
          description: 'Grid cell height is 137 pixels per unit. Minimum cell height is 1 unit.'
        value 'COMPACT', value: 'compact',
          description: 'Grid cell height is 10 pixels per unit. Minimum cell height is 10 units.'
      end
    end
  end
end
