# frozen_string_literal: true

module Projects
  module Security
    class DastScannerProfilesController < Projects::ApplicationController
      include SecurityAndCompliancePermissions

      before_action do
        authorize_read_on_demand_dast_scan!
      end

      feature_category :dynamic_application_security_testing
      urgency :low

      def new; end

      def edit
        @scanner_profile = @project
          .dast_scanner_profiles
          .find(params.permit(:id)[:id])

        render_403 unless @scanner_profile.can_edit_profile?(current_user)
      end
    end
  end
end
