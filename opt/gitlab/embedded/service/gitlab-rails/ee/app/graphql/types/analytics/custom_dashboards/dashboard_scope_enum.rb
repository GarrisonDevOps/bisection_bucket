# frozen_string_literal: true

module Types
  module Analytics
    module CustomDashboards
      class DashboardScopeEnum < BaseEnum
        graphql_name 'CustomDashboardScope'
        description 'Scope filter for custom dashboards'

        value 'ALL', description: 'Return all dashboards.', value: :all
        value 'GITLAB', description: 'Return only GitLab-provided system dashboards.', value: :gitlab
        value 'USER', description: 'Return only user-created dashboards.', value: :user
      end
    end
  end
end
