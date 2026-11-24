# frozen_string_literal: true

module Resolvers
  module Analytics
    module CustomDashboards
      class DashboardResolver < BaseResolver
        include ::Analytics::CustomDashboards::ScopedToCurrentOrganization

        type ::Types::Analytics::CustomDashboards::DashboardType, null: true

        argument :id,
          ::Types::GlobalIDType[::Analytics::CustomDashboards::Dashboard],
          required: true,
          description: 'Dashboard ID.'

        def resolve(id:)
          dashboard = find_current_organization_dashboard(id)
          return unless dashboard
          return unless Ability.allowed?(current_user, :read_custom_dashboard, dashboard)

          dashboard
        end
      end
    end
  end
end
