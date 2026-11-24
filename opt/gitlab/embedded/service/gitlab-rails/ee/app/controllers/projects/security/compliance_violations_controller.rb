# frozen_string_literal: true

module Projects
  module Security
    class ComplianceViolationsController < Projects::ApplicationController
      feature_category :compliance_management

      before_action :authorize_view_violations!

      def show
        @gfm_form = true
        @noteable_type = 'Issue'
      end

      private

      def authorize_view_violations!
        render_404 unless project.licensed_feature_available?(:project_level_compliance_dashboard) &&
          can?(current_user, :read_compliance_dashboard, project)
      end
    end
  end
end
