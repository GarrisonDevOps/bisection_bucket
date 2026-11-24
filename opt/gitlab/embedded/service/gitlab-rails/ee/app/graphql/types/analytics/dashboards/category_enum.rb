# frozen_string_literal: true

module Types
  module Analytics
    module Dashboards
      class CategoryEnum < BaseEnum
        graphql_name 'CustomizableDashboardCategory'
        description 'Categories for customizable dashboards.'

        value 'ANALYTICS', value: 'analytics', description: 'Analytics category for customizable dashboards.'
      end
    end
  end
end
