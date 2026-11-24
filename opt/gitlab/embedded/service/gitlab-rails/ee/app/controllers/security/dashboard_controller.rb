# frozen_string_literal: true

module Security
  class DashboardController < ::Security::ApplicationController
    include GovernUsageGroupTracking

    layout 'instance_security'
    track_internal_event :show, name: 'visit_security_center', category: name

    private

    def tracking_namespace_source
      nil
    end

    def tracking_project_source
      nil
    end
  end
end

Security::DashboardController.prepend_mod
