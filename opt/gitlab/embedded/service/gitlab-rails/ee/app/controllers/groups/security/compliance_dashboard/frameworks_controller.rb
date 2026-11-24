# frozen_string_literal: true

module Groups
  module Security
    module ComplianceDashboard
      class FrameworksController < Groups::ApplicationController
        include Groups::SecurityFeaturesHelper
        include Gitlab::Utils::StrongMemoize

        layout 'group'

        before_action :authorize_compliance_dashboard!

        feature_category :compliance_management

        def show
          respond_to do |format|
            format.json do
              if export_service_response.success?
                send_data(
                  export_service_response.payload,
                  filename: "#{framework.filename}.json",
                  type: 'application/json',
                  disposition: 'attachment'
                )
              else
                render json: { error: export_service_response.message }.to_json, status: :internal_server_error
              end
            end
          end
        end

        private

        def export_service_response
          ComplianceManagement::Frameworks::JsonExportService.new(
            user: current_user,
            group: group,
            framework: framework
          ).execute
        end
        strong_memoize_attr :export_service_response

        def framework
          group.compliance_management_frameworks.find(params.permit(:id)[:id])
        end
        strong_memoize_attr :framework
      end
    end
  end
end
