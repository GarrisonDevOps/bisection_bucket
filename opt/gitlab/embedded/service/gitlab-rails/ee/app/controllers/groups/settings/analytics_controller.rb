# frozen_string_literal: true

module Groups
  module Settings
    class AnalyticsController < Groups::ApplicationController
      include Groups::AnalyticsDashboardHelper

      layout 'group_settings'
      feature_category :custom_dashboards_foundation

      before_action :authorize_analytics_settings!

      def show; end

      def update
        service = ::Groups::UpdateService.new(group, current_user, update_params)
        if service.execute
          flash[:toast] =
            format(s_("Analytics|Analytics settings for '%{group_name}' were successfully updated."),
              group_name: group.name)

          redirect_to group_settings_analytics_path(group)
        else
          @group.reset
          redirect_to group_settings_analytics_path(group),
            alert: s_("Analytics|Unable to update analytics settings. Please try again.")
        end
      end

      private

      def update_params
        params.require(:group).permit(*permitted_group_params)
      end

      def permitted_group_params
        [
          value_stream_dashboard_aggregation_attributes: [
            :enabled
          ],
          analytics_dashboards_pointer_attributes: [:id, :target_project_id],
          insight_attributes: [:id, :project_id]
        ]
      end

      def authorize_analytics_settings!
        access_denied! unless group_analytics_settings_available?(current_user, @group)
      end
    end
  end
end
