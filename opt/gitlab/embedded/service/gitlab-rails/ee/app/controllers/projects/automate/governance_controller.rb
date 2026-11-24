# frozen_string_literal: true

module Projects
  module Automate
    class GovernanceController < Projects::ApplicationController
      feature_category :compliance_management

      before_action :authorize_read_governance!
      before_action do
        push_frontend_feature_flag(:ai_governance_dashboard, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:ai_governance_mcp_server_activity, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:ai_governance_tool_calls, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:ai_governance_connected_agents_filter, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:ai_governance_dashboard_charts, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:ai_governance_skillguard_widget, project.root_ancestor, type: :wip)
        push_frontend_feature_flag(:ai_governance_connected_agents_tab, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:ai_governance_dashboard_side_panels, project.root_ancestor, type: :wip)
        push_frontend_feature_flag(:ai_governance_audit_events_filters, project.root_ancestor, type: :wip)
        push_frontend_feature_flag(:ai_governance_sessions_api, project.root_ancestor, type: :beta)
      end

      def index
        @governance_permitted_tabs = page_availability.permitted_tabs
        @ai_tool_rules_editable =
          @governance_permitted_tabs.include?(::Ai::Governance::PageAvailability::TOOL_MANAGEMENT) &&
          can?(current_user, :update_ai_tool_rule, project.root_ancestor)
        @ai_audit_events_storage_enabled = project.ai_audit_events_storage_enabled
      end

      private

      def authorize_read_governance!
        render_404 unless page_availability.available?
      end

      def page_availability
        @page_availability ||= ::Ai::Governance::PageAvailability
          .new(project, current_user, organization: ::Current.organization)
      end
    end
  end
end
