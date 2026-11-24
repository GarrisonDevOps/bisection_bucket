# frozen_string_literal: true

module Groups
  class MinimalAccessProvisioningAlertDismissalsController < Groups::ApplicationController
    feature_category :seat_cost_management
    urgency :low

    before_action :require_top_level_group
    before_action :authorize_edit_billing!

    def create
      ::GitlabSubscriptions::MemberManagement::DismissMinimalAccessProvisioningAlertService
        .new(current_user: current_user, group: group)
        .execute

      head :ok
    end

    private

    def require_top_level_group
      render_404 if group.subgroup?
    end
  end
end
