# frozen_string_literal: true

module Groups
  module Settings
    module GitlabDuo
      class SeatUtilizationController < Groups::ApplicationController
        before_action :authorize_read_usage_quotas!
        before_action :verify_usage_quotas_enabled!
        before_action :ensure_seat_assignable_duo_add_on!

        feature_category :ai_abstraction_layer

        include ::Nav::GitlabDuoSettingsPage

        def index
          render_404 unless show_gitlab_duo_settings_menu_item?(group)
        end

        private

        def verify_usage_quotas_enabled!
          render_404 unless group.usage_quotas_enabled?
        end

        def ensure_seat_assignable_duo_add_on!
          redirect_to group_settings_gitlab_duo_path(group) unless
            GitlabSubscriptions::AddOnPurchase.for_seat_assignable_duo_add_ons.active.by_namespace(group).any?
        end
      end
    end
  end
end
