# frozen_string_literal: true

module Analytics
  module CustomDashboards
    module OrganizationPolicy
      extend ActiveSupport::Concern

      included do
        condition(:custom_dashboards_feature_enabled) do
          ::Feature.enabled?(:custom_dashboard_storage, @user)
        end

        rule { admin | organization_user }.enable :read_system_dashboard

        rule do
          (admin | organization_user) & custom_dashboards_feature_enabled
        end.enable :read_custom_dashboard

        rule { (admin | organization_owner) & custom_dashboards_feature_enabled }.policy do
          enable :create_custom_dashboard
          enable :update_custom_dashboard
          enable :delete_custom_dashboard
        end
      end
    end
  end
end
