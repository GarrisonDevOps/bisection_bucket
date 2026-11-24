# frozen_string_literal: true

module SeatAlert
  class AdminComponent < BaseComponent
    include LicenseMonitoringHelper

    COMPONENT_BY_STATE = {
      threshold: Admin::ThresholdComponent,
      reached: Admin::ReachedComponent,
      overage: Admin::OverageComponent
    }.freeze

    def initialize(current_user: nil, admin_section: false)
      @current_user = current_user
      @admin_section = admin_section
    end

    def render?
      return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return false unless admin_section?
      return false unless current_user&.can_admin_all_resources?
      return false unless current_license
      return false if small_subscription?
      return false unless current_license.active_user_count_threshold_reached?

      !current_user&.dismissed_callout?(feature_name: Users::CalloutsHelper::ACTIVE_USER_COUNT_THRESHOLD)
    end

    private

    attr_reader :current_user

    def admin_section?
      @admin_section
    end
  end
end
