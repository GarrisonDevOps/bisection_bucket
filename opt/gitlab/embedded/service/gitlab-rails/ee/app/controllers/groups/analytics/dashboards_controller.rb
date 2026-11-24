# frozen_string_literal: true

module Groups
  module Analytics
    class DashboardsController < Groups::Analytics::ApplicationController
      include ProductAnalyticsTracking
      include ::Analytics::RedirectToExploreDashboard

      before_action { authorize_view_by_action!(:read_group_analytics_dashboards) }
      before_action :redirect_to_explore_dashboard, only: [:index]
      before_action do
        [:read_dora4_analytics, :read_cycle_analytics, :read_security_resource].each do |ability|
          push_frontend_ability(ability: ability, resource: @group, user: current_user)
        end

        [:dora4_analytics, :security_dashboard].each do |license|
          push_licensed_feature(license, @group)
        end
      end

      layout 'group'

      private

      def dashboards_container
        group
      end
    end
  end
end
