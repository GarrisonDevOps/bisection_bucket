# frozen_string_literal: true

module Groups
  module Security
    class ComplianceViolationReportsController < Groups::ApplicationController
      include Groups::SecurityFeaturesHelper

      before_action do
        render_404 unless can?(current_user, :read_compliance_violations_report, group)
      end

      feature_category :compliance_management

      def index
        trigger_export
        notifiy_report_is_pending

        redirect_to group_security_compliance_dashboard_path(group, vueroute: :violations)
      end

      private

      def notifiy_report_is_pending
        flash[:notice] = _('After the report is generated, an email will be sent with the report attached.')
      end

      def trigger_export
        ComplianceManagement::Violations::ExportService.new(
          user: current_user,
          namespace: group,
          filters: filter_params.to_h,
          sort: sort_param.to_h
        ).email_export
      end

      def filter_params
        params.permit(
          :merged_after,
          :merged_before,
          :project_ids,
          :target_branch
        )
      end

      def sort_param
        params.permit(:sort)
      end
    end
  end
end
