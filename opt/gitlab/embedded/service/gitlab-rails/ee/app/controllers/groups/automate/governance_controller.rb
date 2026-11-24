# frozen_string_literal: true

module Groups
  module Automate
    class GovernanceController < Groups::ApplicationController
      feature_category :compliance_management

      before_action :authorize_read_governance!
      before_action do
        push_frontend_feature_flag(:ai_governance_dashboard, @group, type: :beta)
        push_frontend_feature_flag(:ai_governance_mcp_server_activity, @group, type: :beta)
        push_frontend_feature_flag(:ai_governance_tool_calls, @group, type: :beta)
        push_frontend_feature_flag(:ai_governance_connected_agents_filter, @group, type: :beta)
        push_frontend_feature_flag(:ai_governance_dashboard_charts, @group, type: :beta)
        push_frontend_feature_flag(:ai_governance_skillguard_widget, @group, type: :wip)
        push_frontend_feature_flag(:ai_governance_connected_agents_tab, @group, type: :beta)
        push_frontend_feature_flag(:ai_governance_dashboard_side_panels, @group, type: :wip)
        push_frontend_feature_flag(:ai_governance_audit_events_filters, @group, type: :wip)
        push_frontend_feature_flag(:ai_governance_sessions_api, @group, type: :beta)
      end

      def index
        @governance_permitted_tabs = page_availability.permitted_tabs
        @ai_audit_events_storage_enabled = group.ai_audit_events_storage_enabled
      end

      private

      def authorize_read_governance!
        render_404 unless page_availability.available?
      end

      def page_availability
        @page_availability ||= ::Ai::Governance::PageAvailability
          .new(group, current_user, organization: ::Current.organization)
      end
    end
  end
end
