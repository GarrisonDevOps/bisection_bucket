# frozen_string_literal: true

module Groups
  module Settings
    class GitlabDuoController < Groups::ApplicationController
      before_action :authorize_read_usage_quotas!
      before_action :verify_usage_quotas_enabled!

      feature_category :ai_abstraction_layer

      include ::Nav::GitlabDuoSettingsPage

      def show
        render_404 unless show_gitlab_duo_settings_menu_item?(group)
      end

      private

      def verify_usage_quotas_enabled!
        render_404 unless group.usage_quotas_enabled?
      end
    end
  end
end
