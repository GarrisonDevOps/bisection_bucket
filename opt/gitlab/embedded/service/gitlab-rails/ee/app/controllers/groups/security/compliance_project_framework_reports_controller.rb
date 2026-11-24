# frozen_string_literal: true

module Groups
  module Security
    class ComplianceProjectFrameworkReportsController < Groups::ApplicationController
      include Groups::SecurityFeaturesHelper

      before_action :authorize_compliance_dashboard!

      feature_category :compliance_management

      def index
        ComplianceManagement::ProjectFrameworks::ExportService.new(user: current_user, namespace: group).email_export

        flash[:notice] = _('After the report is generated, an email will be sent with the report attached.')
        redirect_to group_security_compliance_dashboard_path(group, vueroute: :projects)
      end
    end
  end
end
