# frozen_string_literal: true

module Analytics
  module RedirectToExploreDashboard
    extend ActiveSupport::Concern

    private

    # Explore lists Duo and SDLC trends once a user can reach it, and the namespace copy is
    # hidden, so an existing link is sent to Explore scoped to the namespace it came from.
    def redirect_to_explore_dashboard
      return unless vueroute_param == ::Analytics::Dashboards::Dashboard::AI_IMPACT_DASHBOARD_NAME
      return unless ::Feature.enabled?(:explore_analytics_dashboards, current_user)

      redirect_to explore_analytics_dashboards_path(
        vueroute: ::Analytics::Dashboards::Dashboard::AI_IMPACT_DASHBOARD_NAME,
        scope: dashboards_container.full_path
      )
    end

    def vueroute_param
      params.permit(:vueroute)[:vueroute]
    end
  end
end
