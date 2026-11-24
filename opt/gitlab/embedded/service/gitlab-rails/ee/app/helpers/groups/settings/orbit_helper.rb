# frozen_string_literal: true

module Groups
  module Settings
    module OrbitHelper
      include ::Analytics::Orbit::PlatformHelper

      def group_orbit_settings_data(group)
        hand_raise = hand_raise_modal_dataset(group)

        {
          group_full_path: group.full_path,
          orbit_platform: orbit_platform,
          duo_available: can?(current_user, :access_duo_features, group).to_s,
          orbit_path: dashboard_orbit_path,
          usage_quotas_path: group_usage_quotas_path(group),
          duo_settings_path: group_settings_gitlab_duo_path(group),
          hand_raise_lead_user: hand_raise[:user],
          hand_raise_lead_submit_path: hand_raise[:submit_path]
        }
      end
    end
  end
end
