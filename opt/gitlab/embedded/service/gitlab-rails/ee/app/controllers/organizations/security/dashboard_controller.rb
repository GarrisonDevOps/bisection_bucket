# frozen_string_literal: true

module Organizations
  module Security
    class DashboardController < ::Organizations::ApplicationController
      include Gitlab::InternalEventsTracking

      feature_category :vulnerability_management
      urgency :low

      before_action :ensure_feature_enabled!
      before_action :authorize_read_security_resource!
      before_action only: :show do
        push_frontend_feature_flag(:security_dashboard_mttr_chart, organization)
        push_frontend_feature_flag(:security_dashboard_resolved_by_source_chart, organization)
      end
      after_action :track_visit_upgraded_security_dashboard, only: :show, if: -> { request.format.html? }

      def show; end

      private

      def ensure_feature_enabled!
        render_404 unless Feature.enabled?(:organization_security_dashboard, organization)
      end

      def authorize_read_security_resource!
        render_404 unless can?(current_user, :read_security_resource, organization)
      end

      def track_visit_upgraded_security_dashboard
        track_internal_event(
          'visit_upgraded_security_dashboard',
          user: current_user,
          additional_properties: { organization_id: organization.id }
        )
      end
    end
  end
end
