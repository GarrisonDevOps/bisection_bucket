# frozen_string_literal: true

module Groups
  module Settings
    module GitlabDuo
      class ConfigurationController < Groups::ApplicationController
        feature_category :ai_abstraction_layer

        include ::Nav::GitlabDuoSettingsPage

        before_action :authorize_read_usage_quotas!
        before_action :verify_usage_quotas_enabled!

        before_action do
          push_frontend_feature_flag(:dap_group_customizable_permissions, @group, type: :wip)
          push_frontend_feature_flag(:duo_auto_mode, @group.root_ancestor)
        end

        def index
          redirect_to group_settings_gitlab_duo_path(group) unless render_configuration_page?
        end

        private

        def verify_usage_quotas_enabled!
          render_404 unless group.usage_quotas_enabled?
        end

        def render_configuration_page?
          show_gitlab_duo_settings_menu_item?(group)
        end
      end
    end
  end
end
