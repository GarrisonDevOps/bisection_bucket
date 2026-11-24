# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class DashboardPolicy < BasePolicy
      delegate { @subject.namespace || @subject.organization }

      condition(:is_dashboard_creator) do
        @subject.created_by_id == @user&.id
      end

      condition(:custom_dashboards_feature_enabled) do
        ::Feature.enabled?(:custom_dashboard_storage, @user)
      end

      rule { ~custom_dashboards_feature_enabled }.prevent_all

      rule { can?(:_update_created_custom_dashboard) & is_dashboard_creator }.policy do
        enable :update_custom_dashboard
      end

      rule { can?(:_delete_created_custom_dashboard) & is_dashboard_creator }.policy do
        enable :delete_custom_dashboard
      end
    end
  end
end
