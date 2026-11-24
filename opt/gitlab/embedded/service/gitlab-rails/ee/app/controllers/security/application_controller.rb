# frozen_string_literal: true

module Security
  class ApplicationController < ::ApplicationController
    include SecurityDashboardsPermissions

    feature_category :vulnerability_management
    urgency :low

    protected

    def vulnerable
      @vulnerable ||= InstanceSecurityDashboard.new(current_user)
    end
  end
end
