# frozen_string_literal: true

module Projects
  module Security
    class DastConfigurationController < Projects::ApplicationController
      include SecurityAndCompliancePermissions
      include SecurityDashboardsPermissions

      alias_method :vulnerable, :project

      before_action do
        push_frontend_feature_flag(:dast_pre_scan_verification, @project)
      end

      before_action :check_show_rate_limit!, only: :show

      feature_category :dynamic_application_security_testing
      urgency :low, [:show]

      def show; end

      private

      def check_show_rate_limit!
        return unless Feature.enabled?(:dast_configuration_rate_limit, current_user)

        check_rate_limit!(:dast_configuration_show, scope: { user: current_user })
      end
    end
  end
end
