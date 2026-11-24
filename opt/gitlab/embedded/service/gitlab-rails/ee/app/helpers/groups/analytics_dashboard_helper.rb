# frozen_string_literal: true

module Groups
  module AnalyticsDashboardHelper
    def group_analytics_dashboard_available?(user, group)
      can?(user, :read_group_analytics_dashboards, group)
    end

    def group_analytics_settings_available?(user, group)
      return false unless can?(user, :admin_group, group)

      can_see_analytics_dashboards = group_analytics_dashboard_available?(user, group)
      can_see_insights = group.insights_available?
      can_see_vsd_settings = can?(user, :modify_value_stream_dashboard_settings, group)

      can_see_analytics_dashboards || can_see_insights || can_see_vsd_settings
    end
  end
end
