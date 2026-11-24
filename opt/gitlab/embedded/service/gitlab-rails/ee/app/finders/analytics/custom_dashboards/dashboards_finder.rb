# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class DashboardsFinder
      def initialize(current_user, organization:, params: {})
        @current_user = current_user
        @organization = organization
        @params = params
      end

      def execute
        return Dashboard.none unless can_read_custom_dashboards?

        find_dashboards
      end

      private

      def find_dashboards
        dashboards = @organization.custom_dashboards
        dashboards = by_namespace(dashboards)
        dashboards = by_created_by(dashboards)
        dashboards = by_search(dashboards)
        dashboards = with_namespace_access(dashboards)

        dashboards.order_by_created_at_desc
      end

      def can_read_custom_dashboards?
        Ability.allowed?(@current_user, :read_custom_dashboard, @organization)
      end

      def by_namespace(dashboards)
        return dashboards unless @params[:namespace_id]

        dashboards.by_namespace(@params[:namespace_id])
      end

      def by_created_by(dashboards)
        return dashboards unless @params[:created_by_id]

        dashboards.by_created_by(@params[:created_by_id])
      end

      def by_search(dashboards)
        return dashboards unless @params[:search].present?

        dashboards.search_by_name(@params[:search])
      end

      def with_namespace_access(dashboards)
        org_dashboard = dashboards.org_scoped(@organization.id)

        return org_dashboard unless dashboards.with_namespace.exists?

        authorized_ids = authorized_namespace_ids
        return org_dashboard if authorized_ids.blank?

        namespace_dashboards =
          dashboards.namespace_scoped(@organization.id, authorized_ids)

        Analytics::CustomDashboards::Dashboard.from_union(
          [org_dashboard, namespace_dashboards],
          remove_duplicates: false
        )
      end

      def authorized_namespace_ids
        return [] unless @current_user

        Analytics::CustomDashboards::Dashboard
          .authorized_namespace_ids_for(@current_user, organization: @organization)
      end
    end
  end
end
