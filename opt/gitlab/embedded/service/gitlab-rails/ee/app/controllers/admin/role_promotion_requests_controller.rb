# frozen_string_literal: true

module Admin
  class RolePromotionRequestsController < Admin::ApplicationController
    include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

    feature_category :seat_cost_management
    before_action :verify_role_promotion_requests_enabled!

    def index; end

    private

    def verify_role_promotion_requests_enabled!
      render_404 unless member_promotion_management_enabled?
    end
  end
end
