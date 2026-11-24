# frozen_string_literal: true

module Types
  module Analytics
    module CustomDashboards
      class SystemDashboardType < BaseObject
        graphql_name 'CustomSystemDashboard'

        authorize :read_system_dashboard

        implements Types::Analytics::CustomDashboards::DashboardInterface

        description 'GitLab built-in analytics dashboard (read-only)'

        field :errors, [GraphQL::Types::String], null: true,
          description: 'Schema validation errors in the dashboard configuration, if any.'

        def errors
          object.errors.presence
        end
      end
    end
  end
end
