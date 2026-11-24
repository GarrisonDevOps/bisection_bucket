# frozen_string_literal: true

module Admin
  class MinimalAccessProvisioningAlertDismissalsController < ::Admin::ApplicationController
    feature_category :seat_cost_management
    urgency :low

    def create
      ::GitlabSubscriptions::MemberManagement::DismissMinimalAccessProvisioningAlertService
        .new(current_user: current_user)
        .execute

      head :ok
    end
  end
end
