# frozen_string_literal: true

module Projects
  module Security
    class DashboardController < Projects::ApplicationController
      include SecurityAndCompliancePermissions
      include SecurityDashboardsPermissions
      include GovernUsageProjectTracking

      before_action do
        push_force_frontend_feature_flag(:vulnerabilities_across_contexts, ::Security::VAC.enabled?(project))
        push_frontend_ability(ability: :access_advanced_vulnerability_management, resource: project, user: current_user)
        push_frontend_feature_flag(:security_dashboard_mttr_chart, project)
        push_frontend_feature_flag(:security_dashboard_resolved_by_source_chart, project)
      end

      alias_method :vulnerable, :project

      feature_category :vulnerability_management
      urgency :low
      track_govern_activity 'security_dashboard', :index
      track_internal_event :index, name: 'visit_upgraded_security_dashboard', category: name,
        conditions: -> { upgraded_dashboard_available? }
      track_internal_event :index, name: 'visit_security_dashboard', category: name,
        conditions: -> { !upgraded_dashboard_available? }

      private

      def upgraded_dashboard_available?
        can?(current_user, :access_advanced_vulnerability_management, project)
      end
    end
  end
end
