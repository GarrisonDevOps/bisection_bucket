# frozen_string_literal: true

module Groups
  module Security
    class ComplianceStandardsAdherenceReportsController < Groups::ApplicationController
      include Groups::SecurityFeaturesHelper

      before_action do
        render_404 unless can?(current_user, :read_compliance_adherence_report, group)
      end

      feature_category :compliance_management

      def index
        ComplianceManagement::Standards::ExportService.new(
          user: current_user,
          group: group
        ).email_export

        flash[:notice] = _('After the report is generated, an email will be sent with the report attached.')

        redirect_to group_security_compliance_dashboard_path(group, vueroute: :standards_adherence)
      end
    end
  end
end
